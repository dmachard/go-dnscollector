package loggers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type Webserver struct {
	done       chan bool
	done_api   chan bool
	httpserver net.Listener
	httpmux    *http.ServeMux
	channel    chan dnsutils.DnsMessage
	config     *dnsutils.Config
	logger     *logger.Logger
	stats      *dnsutils.Statistics
}

func NewWebserver(config *dnsutils.Config, logger *logger.Logger) *Webserver {
	logger.Info("webserver - enabled")
	o := &Webserver{
		done:     make(chan bool),
		done_api: make(chan bool),
		config:   config,
		channel:  make(chan dnsutils.DnsMessage, 512),
		logger:   logger,
	}
	// set the config
	o.ReadConfig()

	// init engine to compute statistics
	o.stats = dnsutils.NewStatistics(config.Loggers.WebServer.TopMaxItems)
	return o
}

func (c *Webserver) ReadConfig() {
	// todo, checking value
}

func (o *Webserver) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("webserver - "+msg, v...)
}

func (o *Webserver) LogError(msg string, v ...interface{}) {
	o.logger.Error("webserver - "+msg, v...)
}

func (o *Webserver) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *Webserver) Stop() {
	o.LogInfo("stopping...")

	// stopping http server
	o.httpserver.Close()

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)

	// block and wait until http api is terminated
	<-o.done_api
	close(o.done_api)

	o.LogInfo(" stopped")
}

func (o *Webserver) BasicAuth(w http.ResponseWriter, r *http.Request) bool {
	login, password, authOK := r.BasicAuth()
	if !authOK {
		return false
	}

	return (login == o.config.Loggers.WebServer.BasicAuthLogin) && (password == o.config.Loggers.WebServer.BasicAuthPwd)
}

func (s *Webserver) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:

		suffix := s.config.Loggers.WebServer.PrometheusSuffix
		counters := s.stats.GetCounters()
		topDomains := s.stats.GetTopQnames()
		topClients := s.stats.GetTopClients()

		// total uniq clients
		fmt.Fprintf(w, "# HELP %s_clients_total Number of clients\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_clients_total counter\n", suffix)
		fmt.Fprintf(w, "%s_clients_total %d\n", suffix, s.stats.GetTotalClients())

		// total uniq domains
		fmt.Fprintf(w, "# HELP %s_domains_total Number of domains\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_total counter\n", suffix)
		fmt.Fprintf(w, "%s_domains_total %d\n", suffix, s.stats.GetTotalDomains())

		// pps, qps and rps
		fmt.Fprintf(w, "# HELP %s_pps Number of packet per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_pps gauge\n", suffix)
		fmt.Fprintf(w, "%s_pps %d\n", suffix, counters.Pps)

		fmt.Fprintf(w, "# HELP %s_qps Number of queries per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qps gauge\n", suffix)
		fmt.Fprintf(w, "%s_qps %d\n", suffix, counters.Qps)

		fmt.Fprintf(w, "# HELP %s_rps Number of replies per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rps gauge\n", suffix)
		fmt.Fprintf(w, "%s_rps %d\n", suffix, counters.Rps)

		// max per second
		fmt.Fprintf(w, "# HELP %s_pps_max Maximum number of packet per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_pps_max counter\n", suffix)
		fmt.Fprintf(w, "%s_pps_max %d\n", suffix, counters.Pps_max)

		fmt.Fprintf(w, "# HELP %s_qps_max Maximum number of queries per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qps_max counter\n", suffix)
		fmt.Fprintf(w, "%s_qps_max %d\n", suffix, counters.Qps_max)

		fmt.Fprintf(w, "# HELP %s_rps_max Maximum number of replies per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rps_max counter\n", suffix)
		fmt.Fprintf(w, "%s_rps_max %d\n", suffix, counters.Rps_max)

		// number of queries - udp, tcp, ipv4 and ipv6
		fmt.Fprintf(w, "# HELP %s_queries_total Number of queries received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_total counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_total %d\n", suffix, counters.Queries)

		// queries transport repartition
		fmt.Fprintf(w, "# HELP %s_queries_transport Number of queries transport, partitioned by transport\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_transport counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_transport{transport=\"UDP\"} %d\n", suffix, counters.Queries_udp)
		fmt.Fprintf(w, "%s_queries_transport{transport=\"TCP\"} %d\n", suffix, counters.Queries_tcp)
		fmt.Fprintf(w, "%s_queries_transport{transport=\"DOT\"} %d\n", suffix, counters.Queries_doh)
		fmt.Fprintf(w, "%s_queries_transport{transport=\"DOH\"} %d\n", suffix, counters.Queries_dot)

		// queries family repartition
		fmt.Fprintf(w, "# HELP %s_queries_family Number of replies, partitioned by family\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_family counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_family{family=\"IPv4\"} %d\n", suffix, counters.Queries_ipv4)
		fmt.Fprintf(w, "%s_queries_family{family=\"IPv6\"} %d\n", suffix, counters.Queries_ipv6)

		// number of replies - udp, tcp, ipv4 and ipv6
		fmt.Fprintf(w, "# HELP %s_replies_total Number of responses received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_total counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_total %d\n", suffix, counters.Replies)

		// replies transport repartition
		fmt.Fprintf(w, "# HELP %s_replies_transport Number of replies transport, partitioned by transport\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_transport counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_transport{transport=\"UDP\"} %d\n", suffix, counters.Replies_udp)
		fmt.Fprintf(w, "%s_replies_transport{transport=\"TCP\"} %d\n", suffix, counters.Replies_tcp)
		fmt.Fprintf(w, "%s_replies_transport{transport=\"DOT\"} %d\n", suffix, counters.Replies_doh)
		fmt.Fprintf(w, "%s_replies_transport{transport=\"DOH\"} %d\n", suffix, counters.Replies_dot)

		// replies family repartition
		fmt.Fprintf(w, "# HELP %s_replies_family Number of replies, partitioned by family\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_family counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_family{family=\"IPv4\"} %d\n", suffix, counters.Replies_ipv4)
		fmt.Fprintf(w, "%s_replies_family{family=\"IPv6\"} %d\n", suffix, counters.Replies_ipv6)

		// qtypes repartition
		fmt.Fprintf(w, "# HELP %s_qtypes Number of rtypes, partitioned by qtype\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qtypes counter\n", suffix)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"A\"} %d\n", suffix, counters.Qtype_a)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"AAAA\"} %d\n", suffix, counters.Qtype_aaaa)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"CNAME\"} %d\n", suffix, counters.Qtype_cname)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"TXT\"} %d\n", suffix, counters.Qtype_txt)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"SRV\"} %d\n", suffix, counters.Qtype_srv)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"PTR\"} %d\n", suffix, counters.Qtype_ptr)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"SOA\"} %d\n", suffix, counters.Qtype_soa)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"NS\"} %d\n", suffix, counters.Qtype_ns)
		fmt.Fprintf(w, "%s_qtypes{qtype=\"other\"} %d\n", suffix, counters.Qtype_other)

		// rcodes repartition
		fmt.Fprintf(w, "# HELP %s_rcodes Number of rcodes, partitioned by rcode type\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rcodes counter\n", suffix)
		fmt.Fprintf(w, "%s_rcodes{rcode=\"NOERROR\"} %d\n", suffix, counters.Rcode_noerror)
		fmt.Fprintf(w, "%s_rcodes{rcode=\"NXDOMAIN\"} %d\n", suffix, counters.Rcode_nxdomain)
		fmt.Fprintf(w, "%s_rcodes{rcode=\"REFUSED\"} %d\n", suffix, counters.Rcode_refused)
		fmt.Fprintf(w, "%s_rcodes{rcode=\"SERVFAIL\"} %d\n", suffix, counters.Rcode_servfail)
		fmt.Fprintf(w, "%s_rcodes{rcode=\"NOTIMP\"} %d\n", suffix, counters.Rcode_notimp)
		fmt.Fprintf(w, "%s_rcodes{rcode=\"other\"} %d\n", suffix, counters.Rcode_other)

		// top domains
		fmt.Fprintf(w, "# HELP %s_qnames_top100 Number of qname hit, partitioned by qname\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qnames_top100 counter\n", suffix)
		for _, v := range topDomains {
			fmt.Fprintf(w, "%s_qnames_top100{qname=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}

		// top clients
		fmt.Fprintf(w, "# HELP %s_clients_top100 Number of clients hit, partitioned by client ip\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_clients_top100 counter\n", suffix)
		for _, v := range topClients {
			fmt.Fprintf(w, "%s_clients_top100{ip=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) tablesDomainsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		t := s.stats.GetTopQnames()
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) tablesClientsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		t := s.stats.GetTopClients()
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) tablesRcodesHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		t := s.stats.GetTopRcodes()
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) tablesRrtypesHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		t := s.stats.GetTopRrtypes()
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) tablesOperationsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		t := s.stats.GetTopOperations()
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) ListenAndServe() {
	s.LogInfo("starting http api...")

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.metricsHandler)
	mux.HandleFunc("/tables/domains", s.tablesDomainsHandler)
	mux.HandleFunc("/tables/clients", s.tablesClientsHandler)
	mux.HandleFunc("/tables/rcodes", s.tablesRcodesHandler)
	mux.HandleFunc("/tables/rrtypes", s.tablesRrtypesHandler)
	mux.HandleFunc("/tables/operations", s.tablesOperationsHandler)

	var err error
	var listener net.Listener
	addrlisten := s.config.Loggers.WebServer.ListenIP + ":" + strconv.Itoa(s.config.Loggers.WebServer.ListenPort)
	// listening with tls enabled ?
	if s.config.Loggers.WebServer.TlsSupport {
		s.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(s.config.Loggers.WebServer.CertFile, s.config.Loggers.WebServer.KeyFile)
		if err != nil {
			s.logger.Fatal("loading certificate failed:", err)
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		listener, err = tls.Listen("tcp", addrlisten, config)

	} else {
		// basic listening
		listener, err = net.Listen("tcp", addrlisten)
	}

	// something wrong ?
	if err != nil {
		s.logger.Fatal("listening failed:", err)
	}

	s.httpserver = listener
	s.httpmux = mux
	s.LogInfo("is listening on %s", listener.Addr())

	http.Serve(s.httpserver, s.httpmux)
	s.LogInfo("terminated")
	s.done_api <- true
}

func (s *Webserver) Run() {
	s.LogInfo("running in background...")

	// start http server
	go s.ListenAndServe()

	// init timer to compute qps
	t1_interval := 1 * time.Second
	t1 := time.NewTimer(t1_interval)

LOOP:
	for {
		select {

		case dm, opened := <-s.channel:
			if !opened {
				s.LogInfo("channel closed")
				break LOOP
			}
			// record the dnstap message
			s.stats.Record(dm)

		case <-t1.C:
			// compute qps each second
			s.stats.Compute()

			// reset the timer
			t1.Reset(t1_interval)
		}
	}

	s.LogInfo("run terminated")

	// the job is done
	s.done <- true
}
