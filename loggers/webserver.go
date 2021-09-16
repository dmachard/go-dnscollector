package loggers

import (
	"crypto/tls"
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
		topRcodes := s.stats.GetTopRcodes()
		topRrtypes := s.stats.GetTopRrtypes()
		topTransports := s.stats.GetTopTransports()
		topIpProto := s.stats.GetTopIpProto()
		topOperations := s.stats.GetTopOperations()

		// total uniq clients
		fmt.Fprintf(w, "# HELP %s_clients Number of clients\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_clients counter\n", suffix)
		fmt.Fprintf(w, "%s_clients %d\n", suffix, s.stats.GetTotalClients())

		fmt.Fprintf(w, "# HELP %s_clients_top Number of hit per client, partitioned by client ip\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_clients_top counter\n", suffix)
		for _, v := range topClients {
			fmt.Fprintf(w, "%s_clients_top{ip=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}

		// total uniq domains
		fmt.Fprintf(w, "# HELP %s_domains Number of domains\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains counter\n", suffix)
		fmt.Fprintf(w, "%s_domains %d\n", suffix, s.stats.GetTotalDomains())

		fmt.Fprintf(w, "# HELP %s_domains_top Number of hit per domain, partitioned by qname\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_domains_top counter\n", suffix)
		for _, v := range topDomains {
			fmt.Fprintf(w, "%s_domains_top{domain=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}

		// pps
		fmt.Fprintf(w, "# HELP %s_pps Number of packets per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_pps gauge\n", suffix)
		fmt.Fprintf(w, "%s_pps %d\n", suffix, counters.Pps)

		fmt.Fprintf(w, "# HELP %s_pps_max Maximum number of packets per second received\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_pps_max counter\n", suffix)
		fmt.Fprintf(w, "%s_pps_max %d\n", suffix, counters.PpsMax)

		// number of total packet
		fmt.Fprintf(w, "# HELP %s_packets Number of packets\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_packets counter\n", suffix)
		fmt.Fprintf(w, "%s_packets %d\n", suffix, counters.Packets)

		fmt.Fprintf(w, "# HELP %s_operations Number of packet, partitioned by operations\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_operations counter\n", suffix)
		for _, v := range topOperations {
			fmt.Fprintf(w, "%s_operations{operation=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}

		// transport repartition
		fmt.Fprintf(w, "# HELP %s_transports Number of packets, partitioned by transport\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_transports counter\n", suffix)
		for _, v := range topTransports {
			fmt.Fprintf(w, "%s_transports{transport=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}

		// ip proto repartition
		fmt.Fprintf(w, "# HELP %s_ipproto Number of packets, partitioned by IP protocol\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_ipproto counter\n", suffix)
		for _, v := range topIpProto {
			fmt.Fprintf(w, "%s_ipproto{ip=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}

		// qtypes repartition
		fmt.Fprintf(w, "# HELP %s_qtypes Number of qtypes, partitioned by qtype\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_qtypes counter\n", suffix)
		for _, v := range topRrtypes {
			fmt.Fprintf(w, "%s_qtypes{qtype=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}

		// top rcodes
		fmt.Fprintf(w, "# HELP %s_rcodes Number of rcodes, partitioned by rcode type\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_rcodes counter\n", suffix)
		for _, v := range topRcodes {
			fmt.Fprintf(w, "%s_rcodes{rcode=\"%s\"} %d\n", suffix, v.Name, v.Hit)
		}

		// latency
		fmt.Fprintf(w, "# HELP %s_latency Number of queries answered, partitioned by latency interval\n", suffix)
		fmt.Fprintf(w, "# TYPE %s_latency counter\n", suffix)
		fmt.Fprintf(w, "%s_latency{latency=\"<1ms\"} %d\n", suffix, counters.Latency0_1)
		fmt.Fprintf(w, "%s_latency{latency=\"1-10ms\"} %d\n", suffix, counters.Latency1_10)
		fmt.Fprintf(w, "%s_latency{latency=\"10-50ms\"} %d\n", suffix, counters.Latency10_50)
		fmt.Fprintf(w, "%s_latency{latency=\"50-100ms\"} %d\n", suffix, counters.Latency50_100)
		fmt.Fprintf(w, "%s_latency{latency=\"100-1s\"} %d\n", suffix, counters.Latency100_1000)
		fmt.Fprintf(w, "%s_latency{latency=\">1s\"} %d\n", suffix, counters.Latency1000_inf)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) ListenAndServe() {
	s.LogInfo("starting http api...")

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.metricsHandler)

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
