package loggers

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-topmap"
)

type HitsRecord struct {
	TotalHits int            `json:"total-hits"`
	Hits      map[string]int `json:"hits"`
}

type SearchBy struct {
	Clients map[string]*HitsRecord
	Domains map[string]*HitsRecord
}

type HitsStream struct {
	Streams map[string]SearchBy
}

type HitsUniq struct {
	Clients        map[string]int
	Domains        map[string]int
	NxDomains      map[string]int
	SfDomains      map[string]int
	PublicSuffixes map[string]int
	Suspicious     map[string]*dnsutils.Suspicious
}

type RestAPI struct {
	done       chan bool
	done_api   chan bool
	httpserver net.Listener
	httpmux    *http.ServeMux
	channel    chan dnsutils.DnsMessage
	config     *dnsutils.Config
	logger     *logger.Logger
	name       string

	HitsStream HitsStream
	HitsUniq   HitsUniq

	Streams map[string]int `json:"streams"`

	TopQnames      *topmap.TopMap
	TopClients     *topmap.TopMap
	TopTLDs        *topmap.TopMap
	TopNonExistent *topmap.TopMap
	TopServFail    *topmap.TopMap

	sync.RWMutex
}

func NewRestAPI(config *dnsutils.Config, logger *logger.Logger, version string, name string) *RestAPI {
	logger.Info("[%s] restapi - enabled", name)
	o := &RestAPI{
		done:     make(chan bool),
		done_api: make(chan bool),
		config:   config,
		channel:  make(chan dnsutils.DnsMessage, 512),
		logger:   logger,
		name:     name,

		HitsStream: HitsStream{
			Streams: make(map[string]SearchBy),
		},
		HitsUniq: HitsUniq{
			Clients:        make(map[string]int),
			Domains:        make(map[string]int),
			NxDomains:      make(map[string]int),
			SfDomains:      make(map[string]int),
			PublicSuffixes: make(map[string]int),
			Suspicious:     make(map[string]*dnsutils.Suspicious),
		},

		Streams: make(map[string]int),

		TopQnames:      topmap.NewTopMap(config.Loggers.RestAPI.TopN),
		TopClients:     topmap.NewTopMap(config.Loggers.RestAPI.TopN),
		TopTLDs:        topmap.NewTopMap(config.Loggers.RestAPI.TopN),
		TopNonExistent: topmap.NewTopMap(config.Loggers.RestAPI.TopN),
		TopServFail:    topmap.NewTopMap(config.Loggers.RestAPI.TopN),
	}
	return o
}

func (c *RestAPI) GetName() string { return c.name }

func (c *RestAPI) SetLoggers(loggers []dnsutils.Worker) {}

func (o *RestAPI) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.RestAPI.TlsMinVersion) {
		o.logger.Fatal("logger rest api - invalid tls min version")
	}
}

func (o *RestAPI) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] rest api - "+msg, v...)
}

func (o *RestAPI) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] rest api - "+msg, v...)
}

func (o *RestAPI) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *RestAPI) Stop() {
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

func (o *RestAPI) BasicAuth(w http.ResponseWriter, r *http.Request) bool {
	login, password, authOK := r.BasicAuth()
	if !authOK {
		return false
	}

	return (login == o.config.Loggers.RestAPI.BasicAuthLogin) &&
		(password == o.config.Loggers.RestAPI.BasicAuthPwd)
}

func (s *RestAPI) GetTopTLDsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.TopTLDs.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetTopClientsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.TopClients.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetTopDomainsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.TopQnames.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetTopNxDomainsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.TopNonExistent.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetTopSfDomainsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.TopServFail.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetTLDsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.HitsUniq.PublicSuffixes)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetClientsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.HitsUniq.Clients)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetDomainsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.HitsUniq.Domains)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetNxDomainsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.HitsUniq.NxDomains)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetSfDomainsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.HitsUniq.SfDomains)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetSuspiciousHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.HitsUniq.Suspicious)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetSearchHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:

		streamId := r.URL.Query()["stream_id"]
		queryIp := r.URL.Query()["query_ip"]
		queryName := r.URL.Query()["query_name"]

		if len(streamId) == 0 && len(queryIp) == 0 && len(queryName) == 0 {
			http.Error(w, "Arguments are missing", http.StatusBadRequest)
		}

		// search in a stream
		if len(streamId) == 1 {
			if _, exists := s.HitsStream.Streams[streamId[0]]; exists {
				stream := s.HitsStream.Streams[streamId[0]]

				if len(queryIp) == 1 && len(queryName) == 1 {
					if _, exists := stream.Clients[queryIp[0]]; exists {
						client := stream.Clients[queryIp[0]]
						if _, domainExists := client.Hits[queryName[0]]; domainExists {
							w.Header().Set("Content-Type", "application/text")
							w.Write([]byte(strconv.Itoa(client.Hits[queryName[0]])))
						} else {
							http.Error(w, "{\"error\": \"Query Name not found\"}", http.StatusNotFound)
						}
					} else {
						http.Error(w, "{\"error\": \"Query IP not found\"}", http.StatusNotFound)
					}

				} else if len(queryIp) == 1 {
					if _, exists := stream.Clients[queryIp[0]]; exists {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(stream.Clients[queryIp[0]])
					} else {
						http.Error(w, "{\"error\": \"Query IP not found\"}", http.StatusNotFound)
					}

				} else if len(queryName) == 1 {
					if _, exists := stream.Domains[queryName[0]]; exists {
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(stream.Domains[queryName[0]])
					} else {
						http.Error(w, "{\"error\": \"Query Name not found\"}", http.StatusNotFound)
					}
				}

			} else {
				http.Error(w, "{\"error\": \"Stream ID not Found\"}", http.StatusNotFound)
			}
		}
	default:
		http.Error(w, "{\"error\": \"Method not allowed\"}", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) GetStreamsHandler(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()

	if !s.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.Streams)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *RestAPI) RecordDnsMessage(dm dnsutils.DnsMessage) {
	if _, exists := s.Streams[dm.DnsTap.Identity]; !exists {
		s.Streams[dm.DnsTap.Identity] = 1
	} else {
		s.Streams[dm.DnsTap.Identity] += 1
	}

	// record suspicious domains only is enabled
	if dm.Suspicious != nil {
		if dm.Suspicious.Score > 0.0 {
			if _, exists := s.HitsUniq.Suspicious[dm.DNS.Qname]; !exists {
				s.HitsUniq.Suspicious[dm.DNS.Qname] = dm.Suspicious
			}
		}
	}

	// uniq record for tld
	// record public suffix only if enabled
	if dm.PublicSuffix != nil {
		if dm.PublicSuffix.QnamePublicSuffix != "-" {
			if _, ok := s.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix]; !ok {
				s.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix] = 1
			} else {
				s.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix]++
			}
		}
	}

	// uniq record for domains
	if _, exists := s.HitsUniq.Domains[dm.DNS.Qname]; !exists {
		s.HitsUniq.Domains[dm.DNS.Qname] = 1
	} else {
		s.HitsUniq.Domains[dm.DNS.Qname] += 1
	}

	if dm.DNS.Rcode == dnsutils.DNS_RCODE_NXDOMAIN {
		if _, exists := s.HitsUniq.NxDomains[dm.DNS.Qname]; !exists {
			s.HitsUniq.NxDomains[dm.DNS.Qname] = 1
		} else {
			s.HitsUniq.NxDomains[dm.DNS.Qname] += 1
		}
	}

	if dm.DNS.Rcode == dnsutils.DNS_RCODE_SERVFAIL {
		if _, exists := s.HitsUniq.SfDomains[dm.DNS.Qname]; !exists {
			s.HitsUniq.SfDomains[dm.DNS.Qname] = 1
		} else {
			s.HitsUniq.SfDomains[dm.DNS.Qname] += 1
		}
	}

	// uniq record for queries
	if _, exists := s.HitsUniq.Clients[dm.NetworkInfo.QueryIp]; !exists {
		s.HitsUniq.Clients[dm.NetworkInfo.QueryIp] = 1
	} else {
		s.HitsUniq.Clients[dm.NetworkInfo.QueryIp] += 1
	}

	// uniq top qnames and clients
	s.TopQnames.Record(dm.DNS.Qname, s.HitsUniq.Domains[dm.DNS.Qname])
	s.TopClients.Record(dm.NetworkInfo.QueryIp, s.HitsUniq.Clients[dm.NetworkInfo.QueryIp])
	if dm.PublicSuffix != nil {
		s.TopTLDs.Record(dm.PublicSuffix.QnamePublicSuffix, s.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix])
	}
	if dm.DNS.Rcode == dnsutils.DNS_RCODE_NXDOMAIN {
		s.TopNonExistent.Record(dm.DNS.Qname, s.HitsUniq.NxDomains[dm.DNS.Qname])
	}
	if dm.DNS.Rcode == dnsutils.DNS_RCODE_SERVFAIL {
		s.TopServFail.Record(dm.DNS.Qname, s.HitsUniq.SfDomains[dm.DNS.Qname])
	}

	// record dns message per client source ip and domain
	if _, exists := s.HitsStream.Streams[dm.DnsTap.Identity]; !exists {
		s.HitsStream.Streams[dm.DnsTap.Identity] = SearchBy{Clients: make(map[string]*HitsRecord),
			Domains: make(map[string]*HitsRecord)}
	}

	// continue with the query IP
	if _, exists := s.HitsStream.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp]; !exists {
		s.HitsStream.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp] = &HitsRecord{Hits: make(map[string]int), TotalHits: 1}
	} else {
		s.HitsStream.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp].TotalHits += 1
	}

	// continue with Qname
	if _, exists := s.HitsStream.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp].Hits[dm.DNS.Qname]; !exists {
		s.HitsStream.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp].Hits[dm.DNS.Qname] = 1
	} else {
		s.HitsStream.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp].Hits[dm.DNS.Qname] += 1
	}

	// domain doesn't exists in domains map?
	if _, exists := s.HitsStream.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname]; !exists {
		s.HitsStream.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname] = &HitsRecord{Hits: make(map[string]int), TotalHits: 1}
	} else {
		s.HitsStream.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname].TotalHits += 1
	}

	// domain doesn't exists in domains map?
	if _, exists := s.HitsStream.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIp]; !exists {
		s.HitsStream.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIp] = 1
	} else {
		s.HitsStream.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIp] += 1
	}
}

func (s *RestAPI) ListenAndServe() {
	s.LogInfo("starting server...")

	mux := http.NewServeMux()
	mux.HandleFunc("/tlds", s.GetTLDsHandler)
	mux.HandleFunc("/tlds/top", s.GetTopTLDsHandler)
	mux.HandleFunc("/streams", s.GetStreamsHandler)
	mux.HandleFunc("/clients", s.GetClientsHandler)
	mux.HandleFunc("/clients/top", s.GetTopClientsHandler)
	mux.HandleFunc("/domains", s.GetDomainsHandler)
	mux.HandleFunc("/domains/top", s.GetTopDomainsHandler)
	mux.HandleFunc("/domains/nx", s.GetNxDomainsHandler)
	mux.HandleFunc("/domains/nx/top", s.GetTopNxDomainsHandler)
	mux.HandleFunc("/domains/servfail", s.GetSfDomainsHandler)
	mux.HandleFunc("/domains/servfail/top", s.GetTopSfDomainsHandler)
	mux.HandleFunc("/suspicious", s.GetSuspiciousHandler)
	mux.HandleFunc("/search", s.GetSearchHandler)

	var err error
	var listener net.Listener
	addrlisten := s.config.Loggers.RestAPI.ListenIP + ":" + strconv.Itoa(s.config.Loggers.RestAPI.ListenPort)

	// listening with tls enabled ?
	if s.config.Loggers.RestAPI.TlsSupport {
		s.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(s.config.Loggers.RestAPI.CertFile, s.config.Loggers.RestAPI.KeyFile)
		if err != nil {
			s.logger.Fatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = dnsutils.TLS_VERSION[s.config.Loggers.RestAPI.TlsMinVersion]

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

func (s *RestAPI) Run() {
	s.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, s.channel)
	subprocessors := transformers.NewTransforms(&s.config.OutgoingTransformers, s.logger, s.name, listChannel)

	// start http server
	go s.ListenAndServe()

LOOP:
	for {
		dm, opened := <-s.channel
		if !opened {
			s.LogInfo("channel closed")
			break LOOP
		}

		// apply tranforms
		if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
			continue
		}

		// record the dnstap message
		s.RecordDnsMessage(dm)

	}

	s.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	s.done <- true
}
