package loggers

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
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
	Suspicious     map[string]*dnsutils.TransformSuspicious
}

type KeyHit struct {
	Key string `json:"key"`
	Hit int    `json:"hit"`
}

type RestAPI struct {
	doneAPI     chan bool
	stopProcess chan bool
	doneProcess chan bool
	stopRun     chan bool
	doneRun     chan bool
	inputChan   chan dnsutils.DNSMessage
	outputChan  chan dnsutils.DNSMessage
	httpserver  net.Listener
	httpmux     *http.ServeMux
	config      *pkgconfig.Config
	configChan  chan *pkgconfig.Config
	logger      *logger.Logger
	name        string

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

func NewRestAPI(config *pkgconfig.Config, logger *logger.Logger, name string) *RestAPI {
	logger.Info("[%s] logger=restapi - enabled", name)
	o := &RestAPI{
		doneAPI:     make(chan bool),
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		config:      config,
		configChan:  make(chan *pkgconfig.Config),
		inputChan:   make(chan dnsutils.DNSMessage, config.Loggers.RestAPI.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DNSMessage, config.Loggers.RestAPI.ChannelBufferSize),
		logger:      logger,
		name:        name,

		HitsStream: HitsStream{
			Streams: make(map[string]SearchBy),
		},
		HitsUniq: HitsUniq{
			Clients:        make(map[string]int),
			Domains:        make(map[string]int),
			NxDomains:      make(map[string]int),
			SfDomains:      make(map[string]int),
			PublicSuffixes: make(map[string]int),
			Suspicious:     make(map[string]*dnsutils.TransformSuspicious),
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

func (c *RestAPI) ReadConfig() {
	if !pkgconfig.IsValidTLS(c.config.Loggers.RestAPI.TLSMinVersion) {
		c.logger.Fatal("logger rest api - invalid tls min version")
	}
}

func (c *RestAPI) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *RestAPI) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=restapi - "+msg, v...)
}

func (c *RestAPI) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=restapi - "+msg, v...)
}

func (c *RestAPI) Channel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *RestAPI) Stop() {
	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess

	c.LogInfo("stopping http server...")
	c.httpserver.Close()
	<-c.doneAPI
}

func (c *RestAPI) BasicAuth(w http.ResponseWriter, r *http.Request) bool {
	login, password, authOK := r.BasicAuth()
	if !authOK {
		return false
	}

	return (login == c.config.Loggers.RestAPI.BasicAuthLogin) &&
		(password == c.config.Loggers.RestAPI.BasicAuthPwd)
}

func (c *RestAPI) DeleteResetHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodDelete:

		c.HitsUniq.Clients = make(map[string]int)
		c.HitsUniq.Domains = make(map[string]int)
		c.HitsUniq.NxDomains = make(map[string]int)
		c.HitsUniq.SfDomains = make(map[string]int)
		c.HitsUniq.PublicSuffixes = make(map[string]int)
		c.HitsUniq.Suspicious = make(map[string]*dnsutils.TransformSuspicious)

		c.Streams = make(map[string]int)

		c.TopQnames = topmap.NewTopMap(c.config.Loggers.RestAPI.TopN)
		c.TopClients = topmap.NewTopMap(c.config.Loggers.RestAPI.TopN)
		c.TopTLDs = topmap.NewTopMap(c.config.Loggers.RestAPI.TopN)
		c.TopNonExistent = topmap.NewTopMap(c.config.Loggers.RestAPI.TopN)
		c.TopServFail = topmap.NewTopMap(c.config.Loggers.RestAPI.TopN)

		c.HitsStream.Streams = make(map[string]SearchBy)

		w.Header().Set("Content-Type", "application/text")
		w.Write([]byte("OK"))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetTopTLDsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(c.TopTLDs.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetTopClientsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(c.TopClients.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetTopDomainsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(c.TopQnames.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetTopNxDomainsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(c.TopNonExistent.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetTopSfDomainsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(c.TopServFail.Get())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetTLDsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []KeyHit{}
		for tld, hit := range c.HitsUniq.PublicSuffixes {
			dataArray = append(dataArray, KeyHit{Key: tld, Hit: hit})
		}

		// encode
		json.NewEncoder(w).Encode(dataArray)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetClientsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []KeyHit{}
		for address, hit := range c.HitsUniq.Clients {
			dataArray = append(dataArray, KeyHit{Key: address, Hit: hit})
		}
		// encode
		json.NewEncoder(w).Encode(dataArray)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetDomainsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []KeyHit{}
		for domain, hit := range c.HitsUniq.Domains {
			dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
		}

		// encode
		json.NewEncoder(w).Encode(dataArray)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetNxDomainsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// convert to array
		dataArray := []KeyHit{}
		for domain, hit := range c.HitsUniq.NxDomains {
			dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
		}

		// encode
		json.NewEncoder(w).Encode(dataArray)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetSfDomainsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []KeyHit{}
		for domain, hit := range c.HitsUniq.SfDomains {
			dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
		}

		// encode
		json.NewEncoder(w).Encode(dataArray)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetSuspiciousHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []*dnsutils.TransformSuspicious{}
		for domain, suspicious := range c.HitsUniq.Suspicious {
			suspicious.Domain = domain
			dataArray = append(dataArray, suspicious)
		}

		// encode
		json.NewEncoder(w).Encode(dataArray)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetSearchHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:

		filter := r.URL.Query()["filter"]
		if len(filter) == 0 {
			http.Error(w, "Arguments are missing", http.StatusBadRequest)
		}

		dataArray := []KeyHit{}

		// search by IP
		for _, search := range c.HitsStream.Streams {
			userHits, clientExists := search.Clients[filter[0]]
			if clientExists {
				for domain, hit := range userHits.Hits {
					dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
				}
			}
		}

		// search by domain
		if len(dataArray) == 0 {
			for _, search := range c.HitsStream.Streams {
				domainHists, domainExists := search.Domains[filter[0]]
				if domainExists {
					for addr, hit := range domainHists.Hits {
						dataArray = append(dataArray, KeyHit{Key: addr, Hit: hit})
					}
				}
			}
		}

		// encode to json
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dataArray)

	default:
		http.Error(w, "{\"error\": \"Method not allowed\"}", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) GetStreamsHandler(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	defer c.RUnlock()

	if !c.BasicAuth(w, r) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:

		dataArray := []KeyHit{}
		for stream, hit := range c.Streams {
			dataArray = append(dataArray, KeyHit{Key: stream, Hit: hit})
		}

		json.NewEncoder(w).Encode(dataArray)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *RestAPI) RecordDNSMessage(dm dnsutils.DNSMessage) {
	c.Lock()
	defer c.Unlock()

	if _, exists := c.Streams[dm.DNSTap.Identity]; !exists {
		c.Streams[dm.DNSTap.Identity] = 1
	} else {
		c.Streams[dm.DNSTap.Identity] += 1
	}

	// record suspicious domains only is enabled
	if dm.Suspicious != nil {
		if dm.Suspicious.Score > 0.0 {
			if _, exists := c.HitsUniq.Suspicious[dm.DNS.Qname]; !exists {
				c.HitsUniq.Suspicious[dm.DNS.Qname] = dm.Suspicious
			}
		}
	}

	// uniq record for tld
	// record public suffix only if enabled
	if dm.PublicSuffix != nil {
		if dm.PublicSuffix.QnamePublicSuffix != "-" {
			if _, ok := c.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix]; !ok {
				c.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix] = 1
			} else {
				c.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix]++
			}
		}
	}

	// uniq record for domains
	if _, exists := c.HitsUniq.Domains[dm.DNS.Qname]; !exists {
		c.HitsUniq.Domains[dm.DNS.Qname] = 1
	} else {
		c.HitsUniq.Domains[dm.DNS.Qname] += 1
	}

	if dm.DNS.Rcode == pkgconfig.DNSRcodeNXDomain {
		if _, exists := c.HitsUniq.NxDomains[dm.DNS.Qname]; !exists {
			c.HitsUniq.NxDomains[dm.DNS.Qname] = 1
		} else {
			c.HitsUniq.NxDomains[dm.DNS.Qname] += 1
		}
	}

	if dm.DNS.Rcode == pkgconfig.DNSRcodeServFail {
		if _, exists := c.HitsUniq.SfDomains[dm.DNS.Qname]; !exists {
			c.HitsUniq.SfDomains[dm.DNS.Qname] = 1
		} else {
			c.HitsUniq.SfDomains[dm.DNS.Qname] += 1
		}
	}

	// uniq record for queries
	if _, exists := c.HitsUniq.Clients[dm.NetworkInfo.QueryIP]; !exists {
		c.HitsUniq.Clients[dm.NetworkInfo.QueryIP] = 1
	} else {
		c.HitsUniq.Clients[dm.NetworkInfo.QueryIP] += 1
	}

	// uniq top qnames and clients
	c.TopQnames.Record(dm.DNS.Qname, c.HitsUniq.Domains[dm.DNS.Qname])
	c.TopClients.Record(dm.NetworkInfo.QueryIP, c.HitsUniq.Clients[dm.NetworkInfo.QueryIP])
	if dm.PublicSuffix != nil {
		c.TopTLDs.Record(dm.PublicSuffix.QnamePublicSuffix, c.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix])
	}
	if dm.DNS.Rcode == pkgconfig.DNSRcodeNXDomain {
		c.TopNonExistent.Record(dm.DNS.Qname, c.HitsUniq.NxDomains[dm.DNS.Qname])
	}
	if dm.DNS.Rcode == pkgconfig.DNSRcodeServFail {
		c.TopServFail.Record(dm.DNS.Qname, c.HitsUniq.SfDomains[dm.DNS.Qname])
	}

	// record dns message per client source ip and domain
	if _, exists := c.HitsStream.Streams[dm.DNSTap.Identity]; !exists {
		c.HitsStream.Streams[dm.DNSTap.Identity] = SearchBy{Clients: make(map[string]*HitsRecord),
			Domains: make(map[string]*HitsRecord)}
	}

	// continue with the query IP
	if _, exists := c.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP]; !exists {
		c.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP] = &HitsRecord{Hits: make(map[string]int), TotalHits: 1}
	} else {
		c.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP].TotalHits += 1
	}

	// continue with Qname
	if _, exists := c.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP].Hits[dm.DNS.Qname]; !exists {
		c.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP].Hits[dm.DNS.Qname] = 1
	} else {
		c.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP].Hits[dm.DNS.Qname] += 1
	}

	// domain doesn't exists in domains map?
	if _, exists := c.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname]; !exists {
		c.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname] = &HitsRecord{Hits: make(map[string]int), TotalHits: 1}
	} else {
		c.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname].TotalHits += 1
	}

	// domain doesn't exists in domains map?
	if _, exists := c.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIP]; !exists {
		c.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIP] = 1
	} else {
		c.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIP] += 1
	}
}

func (c *RestAPI) ListenAndServe() {
	c.LogInfo("starting server...")

	mux := http.NewServeMux()
	mux.HandleFunc("/tlds", c.GetTLDsHandler)
	mux.HandleFunc("/tlds/top", c.GetTopTLDsHandler)
	mux.HandleFunc("/streams", c.GetStreamsHandler)
	mux.HandleFunc("/clients", c.GetClientsHandler)
	mux.HandleFunc("/clients/top", c.GetTopClientsHandler)
	mux.HandleFunc("/domains", c.GetDomainsHandler)
	mux.HandleFunc("/domains/servfail", c.GetSfDomainsHandler)
	mux.HandleFunc("/domains/top", c.GetTopDomainsHandler)
	mux.HandleFunc("/domains/nx/top", c.GetTopNxDomainsHandler)
	mux.HandleFunc("/domains/servfail/top", c.GetTopSfDomainsHandler)
	mux.HandleFunc("/suspicious", c.GetSuspiciousHandler)
	mux.HandleFunc("/search", c.GetSearchHandler)
	mux.HandleFunc("/reset", c.DeleteResetHandler)

	var err error
	var listener net.Listener
	addrlisten := c.config.Loggers.RestAPI.ListenIP + ":" + strconv.Itoa(c.config.Loggers.RestAPI.ListenPort)

	// listening with tls enabled ?
	if c.config.Loggers.RestAPI.TLSSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.config.Loggers.RestAPI.CertFile, c.config.Loggers.RestAPI.KeyFile)
		if err != nil {
			c.logger.Fatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = pkgconfig.TLSVersion[c.config.Loggers.RestAPI.TLSMinVersion]

		listener, err = tls.Listen(pkgconfig.SocketTCP, addrlisten, tlsConfig)

	} else {
		// basic listening
		listener, err = net.Listen(pkgconfig.SocketTCP, addrlisten)
	}

	// something wrong ?
	if err != nil {
		c.logger.Fatal("listening failed:", err)
	}

	c.httpserver = listener
	c.httpmux = mux
	c.LogInfo("is listening on %s", listener.Addr())

	http.Serve(c.httpserver, c.httpmux)

	c.LogInfo("http server terminated")
	c.doneAPI <- true
}

func (c *RestAPI) Run() {
	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, c.outputChan)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel, 0)

	// start http server
	go c.ListenAndServe()

	// goroutine to process transformed dns messages
	go c.Process()

	// loop to process incoming messages
	c.LogInfo("ready to process")
RUN_LOOP:
	for {
		select {
		case <-c.stopRun:
			// cleanup transformers
			subprocessors.Reset()
			c.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-c.configChan:
			if !opened {
				return
			}
			c.config = cfg
			c.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-c.inputChan:
			if !opened {
				c.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// send to output channel
			c.outputChan <- dm
		}
	}
	c.LogInfo("run terminated")
}

func (c *RestAPI) Process() {
	c.LogInfo("processing...")

PROCESS_LOOP:
	for {
		select {
		case <-c.stopProcess:
			c.doneProcess <- true
			break PROCESS_LOOP

		case dm, opened := <-c.outputChan:
			if !opened {
				c.LogInfo("output channel closed!")
				return
			}
			// record the dnstap message
			c.RecordDNSMessage(dm)
		}
	}
	c.LogInfo("processing terminated")
}
