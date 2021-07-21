package generators

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

type Qname struct {
	Name string `json:"key"`
	Hit  uint64 `json:"hit"`
}

// sort interface
type ByHit []Qname

func (a ByHit) Len() int           { return len(a) }
func (a ByHit) Less(i, j int) bool { return a[i].Hit < a[j].Hit }
func (a ByHit) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type MapTop struct {
	minvalue uint64
	minindex string
	maxitems int
	qnames   map[string]uint64
	sync.RWMutex
}

func NewMapTop(maxitems int) *MapTop {
	q := &MapTop{
		minvalue: 0,
		minindex: "",
		maxitems: maxitems,
		qnames:   make(map[string]uint64),
	}
	return q
}

func (q *MapTop) FindMin() {
	var minval uint64
	var minkey string
	for k, v := range q.qnames {
		if minval == 0 {
			minval = v
			minkey = k
		} else {
			if v <= minval {
				minval = v
				minkey = k
			}
		}
	}
	q.minvalue = minval
	q.minindex = minkey
}

func (q *MapTop) Record(qname string, hit uint64) {
	q.Lock()
	defer q.Unlock()
	if len(q.qnames) >= q.maxitems {
		if hit > q.minvalue {
			if _, ok := q.qnames[qname]; !ok {
				delete(q.qnames, q.minindex)
			}
			q.qnames[qname] = hit
		}
	} else {
		q.qnames[qname] = hit
	}
	q.FindMin()
}

func (q *MapTop) Get() []Qname {
	q.RLock()
	defer q.RUnlock()

	retMap := []Qname{}
	for k, v := range q.qnames {
		retMap = append(retMap, Qname{k, v})
	}

	sort.Sort(sort.Reverse(ByHit(retMap)))
	return retMap
}

type Counters struct {
	pps uint64
	qps uint64
	rps uint64

	queries_prev uint64
	replies_prev uint64

	queries      uint64
	queries_ipv4 uint64
	queries_ipv6 uint64
	queries_udp  uint64
	queries_tcp  uint64
	queries_doh  uint64
	queries_dot  uint64

	replies      uint64
	replies_ipv4 uint64
	replies_ipv6 uint64
	replies_udp  uint64
	replies_tcp  uint64
	replies_doh  uint64
	replies_dot  uint64

	latency0_1      uint64
	latency1_10     uint64
	latency10_50    uint64
	latency50_100   uint64
	latency100_1000 uint64
	latency1000_inf uint64

	qtype_a     uint64
	qtype_aaaa  uint64
	qtype_cname uint64
	qtype_txt   uint64
	qtype_ptr   uint64
	qtype_soa   uint64
	qtype_ns    uint64
	qtype_srv   uint64
	qtype_other uint64

	rcode_noerror  uint64
	rcode_servfail uint64
	rcode_nxdomain uint64
	rcode_refused  uint64
	rcode_other    uint64
}

type StatisticsMutex struct {
	total         Counters
	qnames        map[string]uint64
	qnamestop     *MapTop
	clients       map[string]uint64
	clientstop    *MapTop
	rrtypes       map[string]uint64
	rrtypestop    *MapTop
	rcodes        map[string]uint64
	rcodestop     *MapTop
	operations    map[string]uint64
	operationstop *MapTop
	rw            sync.RWMutex
}

func (c *StatisticsMutex) Record(dm dnsmessage.DnsMessage) {
	c.rw.Lock()

	if dm.Type == "query" {
		c.total.queries++

		// count number of ipv4 or ipv6
		if dm.Family == "INET" {
			c.total.queries_ipv4++
		} else {
			c.total.queries_ipv6++
		}

		//count number of udp or tcp
		switch dm.Protocol {
		case "UDP":
			c.total.queries_udp++
		case "TCP":
			c.total.queries_tcp++
		case "DOH":
			c.total.queries_doh++
		case "DOT":
			c.total.queries_dot++
		}

	}

	if dm.Type == "reply" {
		c.total.replies++

		// count number of ipv4 or ipv6
		if dm.Family == "INET" {
			c.total.replies_ipv4++
		} else {
			c.total.replies_ipv6++
		}

		//count number of udp or tcp
		switch dm.Protocol {
		case "UDP":
			c.total.replies_udp++
		case "TCP":
			c.total.replies_tcp++
		case "DOH":
			c.total.queries_doh++
		case "DOT":
			c.total.queries_dot++
		}

	}

	switch {
	case dm.Latency == 0.0:
		break
	case dm.Latency > 0.0 && dm.Latency <= 0.001:
		c.total.latency0_1++
	case 0.001 < dm.Latency && dm.Latency <= 0.010:
		c.total.latency1_10++
	case 0.010 < dm.Latency && dm.Latency <= 0.050:
		c.total.latency10_50++
	case 0.050 < dm.Latency && dm.Latency <= 0.100:
		c.total.latency50_100++
	case 0.100 < dm.Latency && dm.Latency <= 1.000:
		c.total.latency100_1000++
	default:
		c.total.latency1000_inf++
	}

	switch {
	case dm.Qtype == "A":
		c.total.qtype_a++
	case dm.Qtype == "AAAA":
		c.total.qtype_aaaa++
	case dm.Qtype == "CNAME":
		c.total.qtype_cname++
	case dm.Qtype == "TXT":
		c.total.qtype_txt++
	case dm.Qtype == "PTR":
		c.total.qtype_ptr++
	case dm.Qtype == "SOA":
		c.total.qtype_soa++
	case dm.Qtype == "NS":
		c.total.qtype_ns++
	case dm.Qtype == "SRV":
		c.total.qtype_srv++
	default:
		c.total.qtype_other++
	}

	switch {
	case dm.Rcode == "NOERROR":
		c.total.rcode_noerror++
	case dm.Rcode == "SERVFAIL":
		c.total.rcode_servfail++
	case dm.Rcode == "NXDOMAIN":
		c.total.rcode_nxdomain++
	case dm.Rcode == "REFUSED":
		c.total.rcode_refused++
	default:
		c.total.rcode_other++
	}

	// record all qnames
	if _, ok := c.qnames[dm.Qname]; !ok {
		c.qnames[dm.Qname] = 1
	} else {
		c.qnames[dm.Qname]++
	}

	// record top qnames
	c.qnamestop.Record(dm.Qname, c.qnames[dm.Qname])

	// record all clients
	if _, ok := c.clients[dm.QueryIp]; !ok {
		c.clients[dm.QueryIp] = 1
	} else {
		c.clients[dm.QueryIp]++
	}

	// record top clients
	c.clientstop.Record(dm.QueryIp, c.clients[dm.QueryIp])

	// record rrtypes
	if _, ok := c.rrtypes[dm.Qtype]; !ok {
		c.rrtypes[dm.Qtype] = 1
	} else {
		c.rrtypes[dm.Qtype]++
	}
	// record top rrtypes
	c.rrtypestop.Record(dm.Qtype, c.rrtypes[dm.Qtype])

	// record rcodes
	if _, ok := c.rcodes[dm.Rcode]; !ok {
		c.rcodes[dm.Rcode] = 1
	} else {
		c.rcodes[dm.Rcode]++
	}
	// record top rcodes
	c.rcodestop.Record(dm.Rcode, c.rcodes[dm.Rcode])

	// recodes operations
	if _, ok := c.operations[dm.Operation]; !ok {
		c.operations[dm.Operation] = 1
	} else {
		c.operations[dm.Operation]++
	}
	// record top operations
	c.operationstop.Record(dm.Operation, c.operations[dm.Operation])

	c.rw.Unlock()
}

func (c *StatisticsMutex) Compute() {
	c.rw.Lock()

	//compute qps
	if c.total.queries > 0 && c.total.queries_prev > 0 {
		c.total.qps = c.total.queries - c.total.queries_prev
	}
	c.total.queries_prev = c.total.queries

	// compute rps
	if c.total.replies > 0 && c.total.replies_prev > 0 {
		c.total.rps = c.total.replies - c.total.replies_prev
	}
	c.total.replies_prev = c.total.replies

	// total pps
	c.total.pps = c.total.qps + c.total.rps

	c.rw.Unlock()
}

func (c *StatisticsMutex) Get() (ret Counters) {
	c.rw.RLock()
	ret = c.total
	c.rw.RUnlock()
	return
}

func (c *StatisticsMutex) GetTotalDomains() (ret int) {
	c.rw.RLock()
	ret = len(c.qnames)
	c.rw.RUnlock()
	return
}

func (c *StatisticsMutex) GetTotalClients() (ret int) {
	c.rw.RLock()
	ret = len(c.clients)
	c.rw.RUnlock()
	return
}

type Metrics struct {
	done        chan bool
	done_api    chan bool
	httpserver  net.Listener
	listenIp    string
	listenPort  int
	topMaxItems int
	channel     chan dnsmessage.DnsMessage
	config      *common.Config
	logger      *logger.Logger
	stats       StatisticsMutex
	testing     bool
}

func NewMetrics(config *common.Config, logger *logger.Logger) *Metrics {
	logger.Info("generator metrics - enabled")
	o := &Metrics{
		done:     make(chan bool),
		done_api: make(chan bool),
		config:   config,
		channel:  make(chan dnsmessage.DnsMessage, 512),
		logger:   logger,
		stats:    StatisticsMutex{},
		testing:  false,
	}
	o.ReadConfig()
	o.stats.total = Counters{}
	o.stats.qnames = make(map[string]uint64)
	o.stats.qnamestop = NewMapTop(o.topMaxItems)
	o.stats.clients = make(map[string]uint64)
	o.stats.clientstop = NewMapTop(o.topMaxItems)
	o.stats.rrtypes = make(map[string]uint64)
	o.stats.rrtypestop = NewMapTop(o.topMaxItems)
	o.stats.rcodes = make(map[string]uint64)
	o.stats.rcodestop = NewMapTop(o.topMaxItems)
	o.stats.operations = make(map[string]uint64)
	o.stats.operationstop = NewMapTop(o.topMaxItems)
	return o
}

func (c *Metrics) ReadConfig() {
	c.listenIp = c.config.Generators.Metrics.ListenIP
	c.listenPort = c.config.Generators.Metrics.ListenPort
	c.topMaxItems = c.config.Generators.Metrics.TopMaxItems
}

func (o *Metrics) Channel() chan dnsmessage.DnsMessage {
	return o.channel
}

func (o *Metrics) Stop() {
	o.logger.Info("generator metrics - stopping...")

	// stopping http server
	o.httpserver.Close()

	// close output channel
	o.logger.Info("generator metrics - closing channel")
	close(o.channel)

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)

	// block and wait until http api is terminated
	<-o.done_api
	close(o.done_api)
}

func (s *Metrics) metricsHandler(w http.ResponseWriter, r *http.Request) {

	suffix := "dnscollector"
	counters := s.stats.Get()

	// total uniq clients
	fmt.Fprintf(w, "# HELP %s_clients_total Number of clients\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_clients_total counter\n", suffix)
	fmt.Fprintf(w, "%s_clients_total %d\n", suffix, s.stats.GetTotalClients())

	// total uniq domains
	fmt.Fprintf(w, "# HELP %s_domains_total Number of domains\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_domains_total counter\n", suffix)
	fmt.Fprintf(w, "%s_domains_total %d\n", suffix, s.stats.GetTotalDomains())

	// pps, qps and rps
	fmt.Fprintf(w, "# HELP %s_pps_total Number of packet per second received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_pps_total gauge\n", suffix)
	fmt.Fprintf(w, "%s_pps_total %d\n", suffix, counters.pps)

	fmt.Fprintf(w, "# HELP %s_qps_total Number of queries per second received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_qps_total gauge\n", suffix)
	fmt.Fprintf(w, "%s_qps_total %d\n", suffix, counters.qps)

	fmt.Fprintf(w, "# HELP %s_rps_total Number of replies per second received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rps_total gauge\n", suffix)
	fmt.Fprintf(w, "%s_rps_total %d\n", suffix, counters.rps)

	// number of queries - udp, tcp, ipv4 and ipv6
	fmt.Fprintf(w, "# HELP %s_queries_total Number of queries received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_queries_total counter\n", suffix)
	fmt.Fprintf(w, "%s_queries_total %d\n", suffix, counters.queries)

	fmt.Fprintf(w, "# HELP %s_queries_udp_total Number of UDP queries received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_queries_udp_total counter\n", suffix)
	fmt.Fprintf(w, "%s_queries_udp_total %d\n", suffix, counters.queries_udp)

	fmt.Fprintf(w, "# HELP %s_queries_tcp_total Number of TCP queries received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_queries_tcp_total counter\n", suffix)
	fmt.Fprintf(w, "%s_queries_tcp_total %d\n", suffix, counters.queries_tcp)

	fmt.Fprintf(w, "# HELP %s_queries_doh_total Number of DOH queries received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_queries_doh_total counter\n", suffix)
	fmt.Fprintf(w, "%s_queries_doh_total %d\n", suffix, counters.queries_doh)

	fmt.Fprintf(w, "# HELP %s_queries_dot_total Number of DOT queries received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_queries_dot_total counter\n", suffix)
	fmt.Fprintf(w, "%s_queries_dot_total %d\n", suffix, counters.queries_dot)

	fmt.Fprintf(w, "# HELP %s_queries_ipv4_total Number of IPv4 queries received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_queries_ipv4_total counter\n", suffix)
	fmt.Fprintf(w, "%s_queries_ipv4_total %d\n", suffix, counters.queries_ipv4)

	fmt.Fprintf(w, "# HELP %s_queries_ipv6_total Number of IPv6 queries received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_queries_ipv6_total counter\n", suffix)
	fmt.Fprintf(w, "%s_queries_ipv6_total %d\n", suffix, counters.queries_ipv6)

	// number of replies - udp, tcp, ipv4 and ipv6
	fmt.Fprintf(w, "# HELP %s_replies_total Number of responses received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_replies_total counter\n", suffix)
	fmt.Fprintf(w, "%s_replies_total %d\n", suffix, counters.replies)

	fmt.Fprintf(w, "# HELP %s_replies_udp_total Number of UDP replies received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_replies_udp_total counter\n", suffix)
	fmt.Fprintf(w, "%s_replies_udp_total %d\n", suffix, counters.replies_udp)

	fmt.Fprintf(w, "# HELP %s_replies_tcp_total Number of TCP replies received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_replies_tcp_total counter\n", suffix)
	fmt.Fprintf(w, "%s_replies_tcp_total %d\n", suffix, counters.replies_tcp)

	fmt.Fprintf(w, "# HELP %s_replies_doh_total Number of DOH replies received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_replies_doh_total counter\n", suffix)
	fmt.Fprintf(w, "%s_replies_doh_total %d\n", suffix, counters.replies_doh)

	fmt.Fprintf(w, "# HELP %s_replies_dot_total Number of DOT replies received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_replies_dot_total counter\n", suffix)
	fmt.Fprintf(w, "%s_replies_dot_total %d\n", suffix, counters.replies_dot)

	fmt.Fprintf(w, "# HELP %s_replies_ipv4_total Number of IPv4 replies received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_replies_ipv4_total counter\n", suffix)
	fmt.Fprintf(w, "%s_replies_ipv4_total %d\n", suffix, counters.replies_ipv4)

	fmt.Fprintf(w, "# HELP %s_replies_ipv6_total Number of IPv6 replies received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_replies_ipv6_total counter\n", suffix)
	fmt.Fprintf(w, "%s_replies_ipv6_total %d\n", suffix, counters.replies_ipv6)

	//rtype
	fmt.Fprintf(w, "# HELP %s_rtype_a_total Number of qtype A received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rtype_a_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rtype_a_total %d\n", suffix, counters.qtype_a)

	fmt.Fprintf(w, "# HELP %s_rtype_aaaa_total Number of qtype AAAA received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rtype_aaaa_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rtype_aaaa_total %d\n", suffix, counters.qtype_aaaa)

	fmt.Fprintf(w, "# HELP %s_rtype_cname_total Number of qtype CNAME received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rtype_cname_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rtype_cname_total %d\n", suffix, counters.qtype_cname)

	fmt.Fprintf(w, "# HELP %s_rtype_txt_total Number of qtype TXT received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rtype_txt_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rtype_txt_total %d\n", suffix, counters.qtype_txt)

	fmt.Fprintf(w, "# HELP %s_rtype_ptr_total Number of qtype PTR received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rtype_ptr_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rtype_ptr_total %d\n", suffix, counters.qtype_ptr)

	fmt.Fprintf(w, "# HELP %s_rtype_srv_total Number of qtype SRV received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rtype_srv_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rtype_srv_total %d\n", suffix, counters.qtype_srv)

	// rcode
	fmt.Fprintf(w, "# HELP %s_rcode_noerror_total Number of rcode NOERROR received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rcode_noerror_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rcode_noerror_total %d\n", suffix, counters.rcode_noerror)

	fmt.Fprintf(w, "# HELP %s_rcode_nxdomain_total Number of rcode NXDOMAIN received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rcode_nxdomain_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rcode_nxdomain_total %d\n", suffix, counters.rcode_nxdomain)

	fmt.Fprintf(w, "# HELP %s_rcode_servfail_total Number of rcode SERVFAIL received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rcode_servfail_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rcode_servfail_total %d\n", suffix, counters.rcode_servfail)

	fmt.Fprintf(w, "# HELP %s_rcode_refused_total Number of rcode REFUSED received\n", suffix)
	fmt.Fprintf(w, "# TYPE %s_rcode_refused_total counter\n", suffix)
	fmt.Fprintf(w, "%s_rcode_refused_total %d\n", suffix, counters.rcode_refused)
}

func (s *Metrics) tablesQnamesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	t := s.stats.qnamestop.Get()
	json.NewEncoder(w).Encode(t)
}

func (s *Metrics) tablesClientsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	t := s.stats.clientstop.Get()
	json.NewEncoder(w).Encode(t)
}

func (s *Metrics) tablesRcodesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	t := s.stats.rcodestop.Get()
	json.NewEncoder(w).Encode(t)
}

func (s *Metrics) tablesRrtypesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	t := s.stats.rrtypestop.Get()
	json.NewEncoder(w).Encode(t)
}

func (s *Metrics) tablesOperationsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	t := s.stats.operationstop.Get()
	json.NewEncoder(w).Encode(t)
}

func (s *Metrics) ServeApi() {
	s.logger.Info("generator httpapi - starting http api...")

	http.HandleFunc("/metrics", s.metricsHandler)
	http.HandleFunc("/tables/domains", s.tablesQnamesHandler)
	http.HandleFunc("/tables/clients", s.tablesClientsHandler)
	http.HandleFunc("/tables/rcodes", s.tablesRcodesHandler)
	http.HandleFunc("/tables/rrtypes", s.tablesRrtypesHandler)
	http.HandleFunc("/tables/operations", s.tablesOperationsHandler)

	listener, err := net.Listen("tcp", s.listenIp+":"+strconv.Itoa(s.listenPort))
	if err != nil {
		s.logger.Fatal("generator httpapi - listen error - ", err)
	}

	s.httpserver = listener
	s.logger.Info("generator httpapi - is listening on %s", listener.Addr())

	http.Serve(listener, nil)
	s.logger.Info("generator httpapi - terminated")
	s.done_api <- true
}

func (s *Metrics) Run() {
	s.logger.Info("generator metrics - running in background...")

	// start http server
	if !s.testing {
		go s.ServeApi()
	}

	// init timer to compute qps
	t1_interval := 1 * time.Second
	t1 := time.NewTimer(t1_interval)

LOOP:
	for {
		select {

		case dm, opened := <-s.channel:
			if !opened {
				s.logger.Info("metrics - channel closed")
				break LOOP
			}
			// record the dnstap message
			s.stats.Record(dm)

			if s.testing {
				break LOOP
			}

		case <-t1.C:
			// compute qps each second
			s.stats.Compute()

			// reset the timer
			t1.Reset(t1_interval)
		}
	}

	s.logger.Info("generator metrics - run terminated")

	// the job is done
	if !s.testing {
		s.done <- true
	}
}
