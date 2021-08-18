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

		fmt.Fprintf(w, "# HELP %s_queries_udp_total Number of UDP queries received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_udp_total counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_udp_total %d\n", suffix, counters.Queries_udp)

		fmt.Fprintf(w, "# HELP %s_queries_tcp_total Number of TCP queries received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_tcp_total counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_tcp_total %d\n", suffix, counters.Queries_tcp)

		fmt.Fprintf(w, "# HELP %s_queries_doh_total Number of DOH queries received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_doh_total counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_doh_total %d\n", suffix, counters.Queries_doh)

		fmt.Fprintf(w, "# HELP %s_queries_dot_total Number of DOT queries received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_dot_total counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_dot_total %d\n", suffix, counters.Queries_dot)

		fmt.Fprintf(w, "# HELP %s_queries_ipv4_total Number of IPv4 queries received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_ipv4_total counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_ipv4_total %d\n", suffix, counters.Queries_ipv4)

		fmt.Fprintf(w, "# HELP %s_queries_ipv6_total Number of IPv6 queries received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_queries_ipv6_total counter\n", suffix)
		fmt.Fprintf(w, "%s_queries_ipv6_total %d\n", suffix, counters.Queries_ipv6)

		// number of replies - udp, tcp, ipv4 and ipv6
		fmt.Fprintf(w, "# HELP %s_replies_total Number of responses received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_total counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_total %d\n", suffix, counters.Replies)

		fmt.Fprintf(w, "# HELP %s_replies_udp_total Number of UDP replies received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_udp_total counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_udp_total %d\n", suffix, counters.Replies_udp)

		fmt.Fprintf(w, "# HELP %s_replies_tcp_total Number of TCP replies received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_tcp_total counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_tcp_total %d\n", suffix, counters.Replies_tcp)

		fmt.Fprintf(w, "# HELP %s_replies_doh_total Number of DOH replies received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_doh_total counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_doh_total %d\n", suffix, counters.Replies_doh)

		fmt.Fprintf(w, "# HELP %s_replies_dot_total Number of DOT replies received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_dot_total counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_dot_total %d\n", suffix, counters.Replies_dot)

		fmt.Fprintf(w, "# HELP %s_replies_ipv4_total Number of IPv4 replies received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_ipv4_total counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_ipv4_total %d\n", suffix, counters.Replies_ipv4)

		fmt.Fprintf(w, "# HELP %s_replies_ipv6_total Number of IPv6 replies received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_replies_ipv6_total counter\n", suffix)
		fmt.Fprintf(w, "%s_replies_ipv6_total %d\n", suffix, counters.Replies_ipv6)

		//rtype
		fmt.Fprintf(w, "# HELP %s_rtype_a_total Number of qtype A received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rtype_a_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rtype_a_total %d\n", suffix, counters.Qtype_a)

		fmt.Fprintf(w, "# HELP %s_rtype_aaaa_total Number of qtype AAAA received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rtype_aaaa_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rtype_aaaa_total %d\n", suffix, counters.Qtype_aaaa)

		fmt.Fprintf(w, "# HELP %s_rtype_cname_total Number of qtype CNAME received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rtype_cname_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rtype_cname_total %d\n", suffix, counters.Qtype_cname)

		fmt.Fprintf(w, "# HELP %s_rtype_txt_total Number of qtype TXT received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rtype_txt_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rtype_txt_total %d\n", suffix, counters.Qtype_txt)

		fmt.Fprintf(w, "# HELP %s_rtype_ptr_total Number of qtype PTR received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rtype_ptr_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rtype_ptr_total %d\n", suffix, counters.Qtype_ptr)

		fmt.Fprintf(w, "# HELP %s_rtype_srv_total Number of qtype SRV received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rtype_srv_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rtype_srv_total %d\n", suffix, counters.Qtype_srv)

		// rcode
		fmt.Fprintf(w, "# HELP %s_rcode_noerror_total Number of rcode NOERROR received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rcode_noerror_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rcode_noerror_total %d\n", suffix, counters.Rcode_noerror)

		fmt.Fprintf(w, "# HELP %s_rcode_nxdomain_total Number of rcode NXDOMAIN received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rcode_nxdomain_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rcode_nxdomain_total %d\n", suffix, counters.Rcode_nxdomain)

		fmt.Fprintf(w, "# HELP %s_rcode_servfail_total Number of rcode SERVFAIL received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rcode_servfail_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rcode_servfail_total %d\n", suffix, counters.Rcode_servfail)

		fmt.Fprintf(w, "# HELP %s_rcode_refused_total Number of rcode REFUSED received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rcode_refused_total counter\n", suffix)
		fmt.Fprintf(w, "%s_rcode_refused_total %d\n", suffix, counters.Rcode_refused)
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
