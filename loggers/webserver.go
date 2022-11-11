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
	stats      *StatsStreams
	ver        string
	name       string
}

func NewWebserver(config *dnsutils.Config, logger *logger.Logger, version string, name string) *Webserver {
	logger.Info("[%s] webserver - enabled", name)
	o := &Webserver{
		done:     make(chan bool),
		done_api: make(chan bool),
		config:   config,
		channel:  make(chan dnsutils.DnsMessage, 512),
		logger:   logger,
		ver:      version,
		name:     name,
	}

	// init engine to compute statistics and prometheus
	o.stats = NewStreamsStats(config, o.ver, config.Loggers.WebServer.PromPrefix,
		config.Loggers.WebServer.StatsTopMaxItems, config.Loggers.WebServer.StatsThresholdQnameLen,
		config.Loggers.WebServer.StatsThresholdPacketLen, config.Loggers.WebServer.StatsThresholdSlow,
		config.Loggers.WebServer.StatsCommonQtypes)
	return o
}

func (c *Webserver) GetName() string { return c.name }

func (c *Webserver) SetLoggers(loggers []dnsutils.Worker) {}

func (o *Webserver) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.WebServer.TlsMinVersion) {
		o.logger.Fatal("logger web server - invalid tls min version")
	}
}

func (o *Webserver) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] webserver - "+msg, v...)
}

func (o *Webserver) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] webserver - "+msg, v...)
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
		stream, ok := r.URL.Query()["stream"]
		if !ok || len(stream) < 1 {
			stream = []string{"global"}
		}
		s.stats.Reset(stream[0])
		fmt.Fprintf(w, "success")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) dumpRequestersHandler(w http.ResponseWriter, r *http.Request) {
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
		t := s.stats.GetClients(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) dumpFqdnsHandler(w http.ResponseWriter, r *http.Request) {
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
		t := s.stats.GetDomains(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) dumpTldsHandler(w http.ResponseWriter, r *http.Request) {
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
		t := s.stats.GetTopFirstLevelDomains(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) dumpAsHandler(w http.ResponseWriter, r *http.Request) {
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
		t := s.stats.GetHitAS(stream[0])
		json.NewEncoder(w).Encode(t)
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

func (s *Webserver) topAllFirstLevelDomainsHandler(w http.ResponseWriter, r *http.Request) {
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
		t := s.stats.GetTopFirstLevelDomains(stream[0])
		json.NewEncoder(w).Encode(t)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Webserver) topAsHandler(w http.ResponseWriter, r *http.Request) {
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
		t := s.stats.GetTopAS(stream[0])
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
	mux.HandleFunc("/reset", s.resetHandler)

	mux.HandleFunc("/top/requesters", s.topRequestersHandler)
	mux.HandleFunc("/top/requesters/suspicious", s.topSuspiciousClientsHandler)
	mux.HandleFunc("/top/tld", s.topAllFirstLevelDomainsHandler)
	mux.HandleFunc("/top/fqdn", s.topAllDomainsHandler)
	mux.HandleFunc("/top/fqdn/nxd", s.topNxdDomainsHandler)
	mux.HandleFunc("/top/fqdn/slow", s.topSlowDomainsHandler)
	mux.HandleFunc("/top/fqdn/suspicious", s.topSuspiciousDomainsHandler)
	mux.HandleFunc("/top/as", s.topAsHandler)

	mux.HandleFunc("/dump/requester", s.dumpRequestersHandler)
	mux.HandleFunc("/dump/fqdn", s.dumpFqdnsHandler)
	mux.HandleFunc("/dump/tld", s.dumpTldsHandler)
	mux.HandleFunc("/dump/as", s.dumpAsHandler)

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

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = dnsutils.TLS_VERSION[s.config.Loggers.Prometheus.TlsMinVersion]

		listener, err = tls.Listen(dnsutils.SOCKET_TCP, addrlisten, tlsConfig)

	} else {
		// basic listening
		listener, err = net.Listen(dnsutils.SOCKET_TCP, addrlisten)
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
