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
	"github.com/dmachard/go-dnscollector/subprocessors"
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
	stats      *subprocessors.StatsStreams
	ver        string
}

func NewWebserver(config *dnsutils.Config, logger *logger.Logger, version string) *Webserver {
	logger.Info("webserver - enabled")
	o := &Webserver{
		done:     make(chan bool),
		done_api: make(chan bool),
		config:   config,
		channel:  make(chan dnsutils.DnsMessage, 512),
		logger:   logger,
		ver:      version,
	}
	// set the config
	o.ReadConfig()

	// init engine to compute statistics
	o.stats = subprocessors.NewStreamsStats(config)
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

func (s *Webserver) resetHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		fmt.Fprintf(w, "success")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:

		suffix := s.config.Loggers.WebServer.PrometheusSuffix

		// add build version info
		fmt.Fprintf(w, "# HELP %s_build_info Build version\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_build_info gauge\n", suffix)
		fmt.Fprintf(w, "%s_build_info{version=\"%s\"} 1\n", suffix, s.ver)

		// docs
		fmt.Fprintf(w, "# HELP %s_requesters_total Number of clients\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_requesters_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_requesters_top_total Number of hit per client, partitioned by client ip\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_requesters_top_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_domains_total Number of domains\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_domains_top_total Number of hit per domain, partitioned by qname\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_top_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_domains_nx_total Number of unknown domains\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_nx_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_domains_nx_top_total Number of hit per unknown domain, partitioned by qname\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_nx_top_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_domains_slow_total Number of slow domains\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_slow_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_domains_slow_top_total Number of hit per slow domain, partitioned by qname\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_slow_top_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_domains_suspicious_total Number of suspicious domains\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_suspicious_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_domains_suspicious_top_total Number of hit per suspicious domains, partitioned by qname\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_suspicious_top_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_pps Number of packets per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_pps gauge\n", suffix)
		fmt.Fprintf(w, "# HELP %s_pps_max_total Maximum number of packets per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_pps_max_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_packets_total Number of packets\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_packets_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_operations_total Number of packet, partitioned by operations\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_operations_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_transports_total Number of packets, partitioned by transport\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_transports_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_ipproto_total Number of packets, partitioned by IP protocol\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_ipproto_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_qtypes_total Number of qtypes, partitioned by qtype\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qtypes_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_rcodes_total Number of rcodes, partitioned by rcode type\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rcodes_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_latency_total Number of queries answered, partitioned by latency interval\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_latency_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_latency_max_total Maximum latency observed\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_latency_max_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_latency_min_total Minimum latency observed\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_latency_min_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_qname_len_total Number of qname, partitioned by qname length\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qname_len_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_qname_len_max_total Maximum qname length observed\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qname_len_max_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_qname_len_min_total Minimum qname length observed\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qname_len_min_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_query_len_total Number of query, partitioned by query length\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_query_len_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_query_len_max_total Maximum query length observed\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_query_len_max_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_query_len_min_total Minimum query length observed\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_query_len_min_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_reply_len_total Number of reply, partitioned by reply length\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_reply_len_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_reply_len_max_total Maximum reply length observed\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_reply_len_max_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_reply_len_min_total Minimum reply length observed\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_reply_len_min_total counter\n", suffix)

		fmt.Fprintf(w, "# HELP %s_packets_malformed_total Number of packets\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_packets_malformed_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_clients_suspicious_total Number of suspicious clients\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_clients_suspicious_total counter\n", suffix)
		fmt.Fprintf(w, "# HELP %s_clients_suspicious_top_total Number of hit per suspicious clients, partitioned by ip\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_clients_suspicious_top_total counter\n", suffix)

		for _, stream := range s.stats.Streams() {

			counters := s.stats.GetCounters(stream)
			totalClients := s.stats.GetTotalClients(stream)

			totalDomains := s.stats.GetTotalDomains(stream)
			topDomains := s.stats.GetTopQnames(stream)

			totalNxdomains := s.stats.GetTotalNxdomains(stream)
			topNxdomains := s.stats.GetTopNxdomains(stream)

			totalSlowdomains := s.stats.GetTotalSlowdomains(stream)
			topSlowdomains := s.stats.GetTopSlowdomains(stream)

			totalSuspiciousdomains := s.stats.GetTotalSuspiciousdomains(stream)
			topSuspiciousdomains := s.stats.GetTopSuspiciousdomains(stream)

			totalSuspiciousClients := s.stats.GetTotalSuspiciousClients(stream)
			topSuspiciousClients := s.stats.GetTopSuspiciousClients(stream)

			topClients := s.stats.GetTopClients(stream)
			topRcodes := s.stats.GetTopRcodes(stream)
			topRrtypes := s.stats.GetTopRrtypes(stream)
			topTransports := s.stats.GetTopTransports(stream)
			topIpProto := s.stats.GetTopIpProto(stream)
			topOperations := s.stats.GetTopOperations(stream)

			// total uniq clients
			fmt.Fprintf(w, "%s_requesters_total{stream=\"%s\"} %d\n", suffix, stream, totalClients)
			for _, v := range topClients {
				fmt.Fprintf(w, "%s_requesters_top_total{stream=\"%s\",ip=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}

			// total uniq domains
			fmt.Fprintf(w, "%s_domains_total{stream=\"%s\"} %d\n", suffix, stream, totalDomains)
			for _, v := range topDomains {
				fmt.Fprintf(w, "%s_domains_top_total{stream=\"%s\",domain=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}
			fmt.Fprintf(w, "%s_domains_nx_total{stream=\"%s\"} %d\n", suffix, stream, totalNxdomains)
			for _, v := range topNxdomains {
				fmt.Fprintf(w, "%s_domains_nx_top_total{stream=\"%s\",domain=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}
			fmt.Fprintf(w, "%s_domains_slow_total{stream=\"%s\"} %d\n", suffix, stream, totalSlowdomains)
			for _, v := range topSlowdomains {
				fmt.Fprintf(w, "%s_domains_slow_top_total{stream=\"%s\",domain=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}
			fmt.Fprintf(w, "%s_domains_suspicious_total{stream=\"%s\"} %d\n", suffix, stream, totalSuspiciousdomains)
			for _, v := range topSuspiciousdomains {
				fmt.Fprintf(w, "%s_domains_suspicious_top_total{stream=\"%s\",domain=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}

			// pps
			fmt.Fprintf(w, "%s_pps{stream=\"%s\"} %d\n", suffix, stream, counters.Pps)
			fmt.Fprintf(w, "%s_pps_max_total{stream=\"%s\"} %d\n", suffix, stream, counters.PpsMax)

			// number of total packet
			fmt.Fprintf(w, "%s_packets_total{stream=\"%s\"} %d\n", suffix, stream, counters.Packets)
			for _, v := range topOperations {
				fmt.Fprintf(w, "%s_operations_total{stream=\"%s\",operation=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}

			// transport repartition
			for _, v := range topTransports {
				fmt.Fprintf(w, "%s_transports_total{stream=\"%s\",transport=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}

			// ip proto repartition
			for _, v := range topIpProto {
				fmt.Fprintf(w, "%s_ipproto_total{stream=\"%s\",ip=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}

			// qtypes repartition
			for _, v := range topRrtypes {
				fmt.Fprintf(w, "%s_qtypes_total{stream=\"%s\",qtype=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}

			// top rcodes
			for _, v := range topRcodes {
				fmt.Fprintf(w, "%s_rcodes_total{stream=\"%s\",rcode=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}

			// latency
			fmt.Fprintf(w, "%s_latency_total{stream=\"%s\",latency=\"<1ms\"} %d\n", suffix, stream, counters.Latency0_1)
			fmt.Fprintf(w, "%s_latency_total{stream=\"%s\",latency=\"1-10ms\"} %d\n", suffix, stream, counters.Latency1_10)
			fmt.Fprintf(w, "%s_latency_total{stream=\"%s\",latency=\"10-50ms\"} %d\n", suffix, stream, counters.Latency10_50)
			fmt.Fprintf(w, "%s_latency_total{stream=\"%s\",latency=\"50-100ms\"} %d\n", suffix, stream, counters.Latency50_100)
			fmt.Fprintf(w, "%s_latency_total{stream=\"%s\",latency=\"100-500ms\"} %d\n", suffix, stream, counters.Latency100_500)
			fmt.Fprintf(w, "%s_latency_total{stream=\"%s\",latency=\"500-1s\"} %d\n", suffix, stream, counters.Latency500_1000)
			fmt.Fprintf(w, "%s_latency_total{stream=\"%s\",latency=\">1s\"} %d\n", suffix, stream, counters.Latency1000_inf)
			fmt.Fprintf(w, "%s_latency_max_total{stream=\"%s\"} %v\n", suffix, stream, counters.LatencyMax)
			fmt.Fprintf(w, "%s_latency_min_total{stream=\"%s\"} %v\n", suffix, stream, counters.LatencyMin)

			// qname length repartition
			fmt.Fprintf(w, "%s_qname_len_total{stream=\"%s\",length=\"<10\"} %d\n", suffix, stream, counters.QnameLength0_10)
			fmt.Fprintf(w, "%s_qname_len_total{stream=\"%s\",length=\"10-20\"} %d\n", suffix, stream, counters.QnameLength10_20)
			fmt.Fprintf(w, "%s_qname_len_total{stream=\"%s\",length=\"20-40\"} %d\n", suffix, stream, counters.QnameLength20_40)
			fmt.Fprintf(w, "%s_qname_len_total{stream=\"%s\",length=\"40-60\"} %d\n", suffix, stream, counters.QnameLength40_60)
			fmt.Fprintf(w, "%s_qname_len_total{stream=\"%s\",length=\"60-100\"} %d\n", suffix, stream, counters.QnameLength60_100)
			fmt.Fprintf(w, "%s_qname_len_total{stream=\"%s\",length=\">100\"} %d\n", suffix, stream, counters.QnameLength100_Inf)
			fmt.Fprintf(w, "%s_qname_len_max_total{stream=\"%s\"} %v\n", suffix, stream, counters.QnameLengthMax)
			fmt.Fprintf(w, "%s_qname_len_min_total{stream=\"%s\"} %v\n", suffix, stream, counters.QnameLengthMin)

			// query length repartition
			fmt.Fprintf(w, "%s_query_len_total{stream=\"%s\",length=\"<50b\"} %d\n", suffix, stream, counters.QueryLength0_50)
			fmt.Fprintf(w, "%s_query_len_total{stream=\"%s\",length=\"50-100b\"} %d\n", suffix, stream, counters.QueryLength50_100)
			fmt.Fprintf(w, "%s_query_len_total{stream=\"%s\",length=\"100-250b\"} %d\n", suffix, stream, counters.QueryLength100_250)
			fmt.Fprintf(w, "%s_query_len_total{stream=\"%s\",length=\"250-500b\"} %d\n", suffix, stream, counters.QueryLength250_500)
			fmt.Fprintf(w, "%s_query_len_total{stream=\"%s\",length=\">500b\"} %d\n", suffix, stream, counters.QueryLength500_Inf)
			fmt.Fprintf(w, "%s_query_len_max_total{stream=\"%s\"} %v\n", suffix, stream, counters.QueryLengthMax)
			fmt.Fprintf(w, "%s_query_len_min_total{stream=\"%s\"} %v\n", suffix, stream, counters.QueryLengthMin)

			// reply length repartition
			fmt.Fprintf(w, "%s_reply_len_total{stream=\"%s\",length=\"<50b\"} %d\n", suffix, stream, counters.ReplyLength0_50)
			fmt.Fprintf(w, "%s_reply_len_total{stream=\"%s\",length=\"50-100b\"} %d\n", suffix, stream, counters.ReplyLength50_100)
			fmt.Fprintf(w, "%s_reply_len_total{stream=\"%s\",length=\"100-250b\"} %d\n", suffix, stream, counters.ReplyLength100_250)
			fmt.Fprintf(w, "%s_reply_len_total{stream=\"%s\",length=\"250-500b\"} %d\n", suffix, stream, counters.ReplyLength250_500)
			fmt.Fprintf(w, "%s_reply_len_total{stream=\"%s\",length=\">500b\"} %d\n", suffix, stream, counters.ReplyLength500_Inf)
			fmt.Fprintf(w, "%s_reply_len_max_total{stream=\"%s\"} %v\n", suffix, stream, counters.ReplyLengthMax)
			fmt.Fprintf(w, "%s_reply_len_min_total{stream=\"%s\"} %v\n", suffix, stream, counters.ReplyLengthMin)

			// add in v0.13.0
			fmt.Fprintf(w, "%s_packets_malformed_total{stream=\"%s\"} %d\n", suffix, stream, counters.PacketsMalformed)
			fmt.Fprintf(w, "%s_clients_suspicious_total{stream=\"%s\"} %d\n", suffix, stream, totalSuspiciousClients)
			for _, v := range topSuspiciousClients {
				fmt.Fprintf(w, "%s_clients_suspicious_top_total{stream=\"%s\",ip=\"%s\"} %d\n", suffix, stream, v.Name, v.Hit)
			}
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) topRequestersHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		stream, ok := r.URL.Query()["stream"]
		if !ok || len(stream) < 1 {
			stream = []string{"global"}
		}
		t := s.stats.GetTopClients(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) topAllDomainsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		stream, ok := r.URL.Query()["stream"]
		if !ok || len(stream) < 1 {
			stream = []string{"global"}
		}
		t := s.stats.GetTopQnames(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) topNxdDomainsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		stream, ok := r.URL.Query()["stream"]
		if !ok || len(stream) < 1 {
			stream = []string{"global"}
		}
		t := s.stats.GetTopNxdomains(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) topSlowDomainsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		stream, ok := r.URL.Query()["stream"]
		if !ok || len(stream) < 1 {
			stream = []string{"global"}
		}
		t := s.stats.GetTopSlowdomains(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) topSuspiciousDomainsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		stream, ok := r.URL.Query()["stream"]
		if !ok || len(stream) < 1 {
			stream = []string{"global"}
		}
		t := s.stats.GetTopSuspiciousdomains(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) topSuspiciousClientsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		stream, ok := r.URL.Query()["stream"]
		if !ok || len(stream) < 1 {
			stream = []string{"global"}
		}
		t := s.stats.GetTopSuspiciousClients(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) ListenAndServe() {
	s.LogInfo("starting http api...")

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.metricsHandler)
	mux.HandleFunc("/reset", s.resetHandler)
	mux.HandleFunc("/top/requesters", s.topRequestersHandler)
	mux.HandleFunc("/top/domains", s.topAllDomainsHandler)
	mux.HandleFunc("/top/domains/nxd", s.topNxdDomainsHandler)
	mux.HandleFunc("/top/domains/slow", s.topSlowDomainsHandler)
	mux.HandleFunc("/top/domains/suspicious", s.topSuspiciousDomainsHandler)
	mux.HandleFunc("/top/clients/suspicious", s.topSuspiciousClientsHandler)

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
