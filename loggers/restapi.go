package loggers

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
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
	*pkgutils.GenericWorker
	doneAPI    chan bool
	httpserver net.Listener
	httpmux    *http.ServeMux

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
	w := &RestAPI{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "restapi", config.Loggers.RestAPI.ChannelBufferSize)}
	w.HitsStream = HitsStream{
		Streams: make(map[string]SearchBy),
	}
	w.HitsUniq = HitsUniq{
		Clients:        make(map[string]int),
		Domains:        make(map[string]int),
		NxDomains:      make(map[string]int),
		SfDomains:      make(map[string]int),
		PublicSuffixes: make(map[string]int),
		Suspicious:     make(map[string]*dnsutils.TransformSuspicious),
	}
	w.Streams = make(map[string]int)
	w.TopQnames = topmap.NewTopMap(config.Loggers.RestAPI.TopN)
	w.TopClients = topmap.NewTopMap(config.Loggers.RestAPI.TopN)
	w.TopTLDs = topmap.NewTopMap(config.Loggers.RestAPI.TopN)
	w.TopNonExistent = topmap.NewTopMap(config.Loggers.RestAPI.TopN)
	w.TopServFail = topmap.NewTopMap(config.Loggers.RestAPI.TopN)
	return w
}

func (w *RestAPI) ReadConfig() {
	if !pkgconfig.IsValidTLS(w.GetConfig().Loggers.RestAPI.TLSMinVersion) {
		w.LogFatal(pkgutils.PrefixLogLogger + "[" + w.GetName() + "]restapi - invalid tls min version")
	}
}

func (w *RestAPI) BasicAuth(httpWriter http.ResponseWriter, r *http.Request) bool {
	login, password, authOK := r.BasicAuth()
	if !authOK {
		return false
	}

	return (login == w.GetConfig().Loggers.RestAPI.BasicAuthLogin) &&
		(password == w.GetConfig().Loggers.RestAPI.BasicAuthPwd)
}

func (w *RestAPI) DeleteResetHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodDelete:

		w.HitsUniq.Clients = make(map[string]int)
		w.HitsUniq.Domains = make(map[string]int)
		w.HitsUniq.NxDomains = make(map[string]int)
		w.HitsUniq.SfDomains = make(map[string]int)
		w.HitsUniq.PublicSuffixes = make(map[string]int)
		w.HitsUniq.Suspicious = make(map[string]*dnsutils.TransformSuspicious)

		w.Streams = make(map[string]int)

		w.TopQnames = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)
		w.TopClients = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)
		w.TopTLDs = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)
		w.TopNonExistent = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)
		w.TopServFail = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)

		w.HitsStream.Streams = make(map[string]SearchBy)

		httpWriter.Header().Set("Content-Type", "application/text")
		httpWriter.Write([]byte("OK"))
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopTLDsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopTLDs.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopClientsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopClients.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopQnames.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopNxDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopNonExistent.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopSfDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopServFail.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTLDsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []KeyHit{}
		for tld, hit := range w.HitsUniq.PublicSuffixes {
			dataArray = append(dataArray, KeyHit{Key: tld, Hit: hit})
		}

		// encode
		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetClientsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []KeyHit{}
		for address, hit := range w.HitsUniq.Clients {
			dataArray = append(dataArray, KeyHit{Key: address, Hit: hit})
		}
		// encode
		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []KeyHit{}
		for domain, hit := range w.HitsUniq.Domains {
			dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
		}

		// encode
		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetNxDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// convert to array
		dataArray := []KeyHit{}
		for domain, hit := range w.HitsUniq.NxDomains {
			dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
		}

		// encode
		json.NewEncoder(httpWriter).Encode(dataArray)

	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetSfDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []KeyHit{}
		for domain, hit := range w.HitsUniq.SfDomains {
			dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
		}

		// encode
		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetSuspiciousHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// return as array
		dataArray := []*dnsutils.TransformSuspicious{}
		for domain, suspicious := range w.HitsUniq.Suspicious {
			suspicious.Domain = domain
			dataArray = append(dataArray, suspicious)
		}

		// encode
		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetSearchHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:

		filter := r.URL.Query()["filter"]
		if len(filter) == 0 {
			http.Error(httpWriter, "Arguments are missing", http.StatusBadRequest)
		}

		dataArray := []KeyHit{}

		// search by IP
		for _, search := range w.HitsStream.Streams {
			userHits, clientExists := search.Clients[filter[0]]
			if clientExists {
				for domain, hit := range userHits.Hits {
					dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
				}
			}
		}

		// search by domain
		if len(dataArray) == 0 {
			for _, search := range w.HitsStream.Streams {
				domainHists, domainExists := search.Domains[filter[0]]
				if domainExists {
					for addr, hit := range domainHists.Hits {
						dataArray = append(dataArray, KeyHit{Key: addr, Hit: hit})
					}
				}
			}
		}

		// encode to json
		httpWriter.Header().Set("Content-Type", "application/json")
		json.NewEncoder(httpWriter).Encode(dataArray)

	default:
		http.Error(httpWriter, "{\"error\": \"Method not allowed\"}", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetStreamsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:

		dataArray := []KeyHit{}
		for stream, hit := range w.Streams {
			dataArray = append(dataArray, KeyHit{Key: stream, Hit: hit})
		}

		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) RecordDNSMessage(dm dnsutils.DNSMessage) {
	w.Lock()
	defer w.Unlock()

	if _, exists := w.Streams[dm.DNSTap.Identity]; !exists {
		w.Streams[dm.DNSTap.Identity] = 1
	} else {
		w.Streams[dm.DNSTap.Identity] += 1
	}

	// record suspicious domains only is enabled
	if dm.Suspicious != nil {
		if dm.Suspicious.Score > 0.0 {
			if _, exists := w.HitsUniq.Suspicious[dm.DNS.Qname]; !exists {
				w.HitsUniq.Suspicious[dm.DNS.Qname] = dm.Suspicious
			}
		}
	}

	// uniq record for tld
	// record public suffix only if enabled
	if dm.PublicSuffix != nil {
		if dm.PublicSuffix.QnamePublicSuffix != "-" {
			if _, ok := w.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix]; !ok {
				w.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix] = 1
			} else {
				w.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix]++
			}
		}
	}

	// uniq record for domains
	if _, exists := w.HitsUniq.Domains[dm.DNS.Qname]; !exists {
		w.HitsUniq.Domains[dm.DNS.Qname] = 1
	} else {
		w.HitsUniq.Domains[dm.DNS.Qname] += 1
	}

	if dm.DNS.Rcode == dnsutils.DNSRcodeNXDomain {
		if _, exists := w.HitsUniq.NxDomains[dm.DNS.Qname]; !exists {
			w.HitsUniq.NxDomains[dm.DNS.Qname] = 1
		} else {
			w.HitsUniq.NxDomains[dm.DNS.Qname] += 1
		}
	}

	if dm.DNS.Rcode == dnsutils.DNSRcodeServFail {
		if _, exists := w.HitsUniq.SfDomains[dm.DNS.Qname]; !exists {
			w.HitsUniq.SfDomains[dm.DNS.Qname] = 1
		} else {
			w.HitsUniq.SfDomains[dm.DNS.Qname] += 1
		}
	}

	// uniq record for queries
	if _, exists := w.HitsUniq.Clients[dm.NetworkInfo.QueryIP]; !exists {
		w.HitsUniq.Clients[dm.NetworkInfo.QueryIP] = 1
	} else {
		w.HitsUniq.Clients[dm.NetworkInfo.QueryIP] += 1
	}

	// uniq top qnames and clients
	w.TopQnames.Record(dm.DNS.Qname, w.HitsUniq.Domains[dm.DNS.Qname])
	w.TopClients.Record(dm.NetworkInfo.QueryIP, w.HitsUniq.Clients[dm.NetworkInfo.QueryIP])
	if dm.PublicSuffix != nil {
		w.TopTLDs.Record(dm.PublicSuffix.QnamePublicSuffix, w.HitsUniq.PublicSuffixes[dm.PublicSuffix.QnamePublicSuffix])
	}
	if dm.DNS.Rcode == dnsutils.DNSRcodeNXDomain {
		w.TopNonExistent.Record(dm.DNS.Qname, w.HitsUniq.NxDomains[dm.DNS.Qname])
	}
	if dm.DNS.Rcode == dnsutils.DNSRcodeServFail {
		w.TopServFail.Record(dm.DNS.Qname, w.HitsUniq.SfDomains[dm.DNS.Qname])
	}

	// record dns message per client source ip and domain
	if _, exists := w.HitsStream.Streams[dm.DNSTap.Identity]; !exists {
		w.HitsStream.Streams[dm.DNSTap.Identity] = SearchBy{Clients: make(map[string]*HitsRecord),
			Domains: make(map[string]*HitsRecord)}
	}

	// continue with the query IP
	if _, exists := w.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP]; !exists {
		w.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP] = &HitsRecord{Hits: make(map[string]int), TotalHits: 1}
	} else {
		w.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP].TotalHits += 1
	}

	// continue with Qname
	if _, exists := w.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP].Hits[dm.DNS.Qname]; !exists {
		w.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP].Hits[dm.DNS.Qname] = 1
	} else {
		w.HitsStream.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP].Hits[dm.DNS.Qname] += 1
	}

	// domain doesn't exists in domains map?
	if _, exists := w.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname]; !exists {
		w.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname] = &HitsRecord{Hits: make(map[string]int), TotalHits: 1}
	} else {
		w.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname].TotalHits += 1
	}

	// domain doesn't exists in domains map?
	if _, exists := w.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIP]; !exists {
		w.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIP] = 1
	} else {
		w.HitsStream.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname].Hits[dm.NetworkInfo.QueryIP] += 1
	}
}

func (w *RestAPI) ListenAndServe() {
	w.LogInfo("starting server...")

	mux := http.NewServeMux()
	mux.HandleFunc("/tlds", w.GetTLDsHandler)
	mux.HandleFunc("/tlds/top", w.GetTopTLDsHandler)
	mux.HandleFunc("/streams", w.GetStreamsHandler)
	mux.HandleFunc("/clients", w.GetClientsHandler)
	mux.HandleFunc("/clients/top", w.GetTopClientsHandler)
	mux.HandleFunc("/domains", w.GetDomainsHandler)
	mux.HandleFunc("/domains/servfail", w.GetSfDomainsHandler)
	mux.HandleFunc("/domains/top", w.GetTopDomainsHandler)
	mux.HandleFunc("/domains/nx/top", w.GetTopNxDomainsHandler)
	mux.HandleFunc("/domains/servfail/top", w.GetTopSfDomainsHandler)
	mux.HandleFunc("/suspicious", w.GetSuspiciousHandler)
	mux.HandleFunc("/search", w.GetSearchHandler)
	mux.HandleFunc("/reset", w.DeleteResetHandler)

	var err error
	var listener net.Listener
	addrlisten := w.GetConfig().Loggers.RestAPI.ListenIP + ":" + strconv.Itoa(w.GetConfig().Loggers.RestAPI.ListenPort)

	// listening with tls enabled ?
	if w.GetConfig().Loggers.RestAPI.TLSSupport {
		w.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(w.GetConfig().Loggers.RestAPI.CertFile, w.GetConfig().Loggers.RestAPI.KeyFile)
		if err != nil {
			w.LogFatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = pkgconfig.TLSVersion[w.GetConfig().Loggers.RestAPI.TLSMinVersion]

		listener, err = tls.Listen(netutils.SocketTCP, addrlisten, tlsConfig)

	} else {
		// basic listening
		listener, err = net.Listen(netutils.SocketTCP, addrlisten)
	}

	// something wrong ?
	if err != nil {
		w.LogFatal("listening failed:", err)
	}

	w.httpserver = listener
	w.httpmux = mux
	w.LogInfo("is listening on %s", listener.Addr())

	http.Serve(w.httpserver, w.httpmux)

	w.LogInfo("http server terminated")
	w.doneAPI <- true
}

func (w *RestAPI) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := pkgutils.GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := pkgutils.GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// start http server
	go w.ListenAndServe()

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()

			w.httpserver.Close()
			<-w.doneAPI

			return

			// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *RestAPI) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}
			// record the dnstap message
			w.RecordDNSMessage(dm)
		}
	}
}
