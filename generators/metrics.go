package generators

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

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
	stats       *Statistics
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
		testing:  false,
	}
	// set the config
	o.ReadConfig()

	// init engine to compute statistics
	o.stats = NewStatistics(o.topMaxItems)
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
