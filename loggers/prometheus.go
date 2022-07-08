package loggers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-topmap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Prometheus struct {
	done         chan bool
	done_api     chan bool
	httpserver   net.Listener
	channel      chan dnsutils.DnsMessage
	config       *dnsutils.Config
	logger       *logger.Logger
	promRegistry *prometheus.Registry
	version      string

	requesters map[string]map[string]int
	domains    map[string]map[string]int
	nxdomains  map[string]map[string]int

	topDomains    map[string]*topmap.TopMap
	topNxDomains  map[string]*topmap.TopMap
	topRequesters map[string]*topmap.TopMap

	gaugeBuildInfo     *prometheus.GaugeVec
	gaugeTopDomains    *prometheus.GaugeVec
	gaugeTopNxDomains  *prometheus.GaugeVec
	gaugeTopRequesters *prometheus.GaugeVec

	counterPackets        *prometheus.CounterVec
	counterInvalidPackets *prometheus.CounterVec
	counterQueries        *prometheus.CounterVec
	counterReplies        *prometheus.CounterVec
	counterRcodes         *prometheus.CounterVec
	counterQtypes         *prometheus.CounterVec
	counterProtocols      *prometheus.CounterVec
	counterFamilies       *prometheus.CounterVec
	counterOperations     *prometheus.CounterVec
	counterFlagsTC        *prometheus.CounterVec
	counterFlagsAA        *prometheus.CounterVec
	counterFlagsRA        *prometheus.CounterVec
	counterFlagsAD        *prometheus.CounterVec
	counterReceivedBytes  *prometheus.CounterVec
	counterSentBytes      *prometheus.CounterVec
	counterDomains        *prometheus.CounterVec
	counterDomainsNX      *prometheus.CounterVec
	counterRequesters     *prometheus.CounterVec

	histogramQueriesLength *prometheus.HistogramVec
	histogramRepliesLength *prometheus.HistogramVec
	histogramQnamesLength  *prometheus.HistogramVec
	histogramLatencies     *prometheus.HistogramVec

	name string
}

func NewPrometheus(config *dnsutils.Config, logger *logger.Logger, version string, name string) *Prometheus {
	logger.Info("[%s] logger to prometheus - enabled", name)
	o := &Prometheus{
		done:         make(chan bool),
		done_api:     make(chan bool),
		config:       config,
		channel:      make(chan dnsutils.DnsMessage, 512),
		logger:       logger,
		version:      version,
		promRegistry: prometheus.NewRegistry(),

		requesters: make(map[string]map[string]int),
		domains:    make(map[string]map[string]int),
		nxdomains:  make(map[string]map[string]int),

		topDomains:    make(map[string]*topmap.TopMap),
		topNxDomains:  make(map[string]*topmap.TopMap),
		topRequesters: make(map[string]*topmap.TopMap),

		name: name,
	}
	o.InitProm()

	// add build version in metrics
	o.gaugeBuildInfo.WithLabelValues(o.version).Set(1)

	return o
}

func (o *Prometheus) InitProm() {
	o.gaugeBuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_build_info", o.config.Loggers.Prometheus.PromPrefix),
			Help: "Build version",
		},
		[]string{"version"},
	)
	o.promRegistry.MustRegister(o.gaugeBuildInfo)

	o.gaugeTopDomains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_domains_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "Number of hit per domain topN, partitioned by qname",
		},
		[]string{"stream", "domain"},
	)
	o.promRegistry.MustRegister(o.gaugeTopDomains)

	o.gaugeTopNxDomains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_nxdomains_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "Number of hit per nx domain topN, partitioned by qname",
		},
		[]string{"stream", "domain"},
	)
	o.promRegistry.MustRegister(o.gaugeTopNxDomains)

	o.gaugeTopRequesters = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_requesters_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "Number of hit per requester topN, partitioned by qname",
		},
		[]string{"stream", "domain"},
	)
	o.promRegistry.MustRegister(o.gaugeTopRequesters)

	o.counterPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_packets_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of packets",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterPackets)

	o.counterQueries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_queries_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of queries",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterQueries)

	o.counterReplies = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_replies_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of replies",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterReplies)

	o.counterInvalidPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_packets_invalid_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of invalid packets",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterInvalidPackets)

	o.histogramQueriesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_queries_size_bytes", o.config.Loggers.Prometheus.PromPrefix),
			Help:    "Size of the queries in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.histogramQueriesLength)

	o.histogramRepliesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_replies_size_bytes", o.config.Loggers.Prometheus.PromPrefix),
			Help:    "Size of the replies in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.histogramRepliesLength)

	o.histogramQnamesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_qnames_size_bytes", o.config.Loggers.Prometheus.PromPrefix),
			Help:    "Size of the qname in bytes.",
			Buckets: []float64{10, 20, 40, 60, 100},
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.histogramQnamesLength)

	o.histogramLatencies = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_latencies", o.config.Loggers.Prometheus.PromPrefix),
			Help:    "Latency between query and reply",
			Buckets: []float64{0.001, 0.010, 0.050, 0.100, 0.5, 1.0},
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.histogramLatencies)

	o.counterRcodes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_rcodes_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of replies per rcode",
		},
		[]string{"stream", "rcode"},
	)
	o.promRegistry.MustRegister(o.counterRcodes)

	o.counterQtypes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_qtypes_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of qtypes, partitioned by qtype",
		},
		[]string{"stream", "qtype"},
	)
	o.promRegistry.MustRegister(o.counterQtypes)

	o.counterProtocols = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_protocols_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of packets, partitioned by protocols (tcp, udp, ...)",
		},
		[]string{"stream", "protocol"},
	)
	o.promRegistry.MustRegister(o.counterProtocols)

	o.counterFamilies = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_family_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of packets, partitioned by family (IPv4, IPv6)",
		},
		[]string{"stream", "family"},
	)
	o.promRegistry.MustRegister(o.counterFamilies)

	o.counterOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_operations_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of packet, partitioned by operations",
		},
		[]string{"stream", "operation"},
	)
	o.promRegistry.MustRegister(o.counterOperations)

	o.counterReceivedBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_sent_bytes_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total bytes sent",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterReceivedBytes)

	o.counterSentBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_received_bytes_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total bytes received",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterSentBytes)

	o.counterFlagsTC = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_truncated_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total of replies with TC flag",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterFlagsTC)

	o.counterFlagsAA = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_authoritative_answer_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total replies with AA flag",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterFlagsAA)

	o.counterFlagsRA = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_recursion_available_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total replies with RA flag",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterFlagsRA)

	o.counterFlagsAD = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_authentic_data_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total replies with AD flag",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterFlagsAD)

	o.counterDomains = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_domains_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of domains",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterDomains)

	o.counterDomainsNX = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_domains_nx_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of unknown domains",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterDomainsNX)

	o.counterRequesters = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_requesters_total", o.config.Loggers.Prometheus.PromPrefix),
			Help: "The total number of DNS clients",
		},
		[]string{"stream"},
	)
	o.promRegistry.MustRegister(o.counterRequesters)
}

func (o *Prometheus) ReadConfig() {
}

func (o *Prometheus) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] prometheus - "+msg, v...)
}

func (o *Prometheus) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] prometheus - "+msg, v...)
}

func (o *Prometheus) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *Prometheus) Stop() {
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

func (o *Prometheus) BasicAuth(w http.ResponseWriter, r *http.Request) bool {
	login, password, authOK := r.BasicAuth()
	if !authOK {
		return false
	}

	return (login == o.config.Loggers.Prometheus.BasicAuthLogin) && (password == o.config.Loggers.Prometheus.BasicAuthPwd)
}

func (o *Prometheus) Record(dm dnsutils.DnsMessage) {
	// count number of logs according to the stream name
	o.counterPackets.WithLabelValues(dm.DnsTap.Identity).Inc()

	// count the number of invalid packet according to the stream name
	if dm.DNS.MalformedPacket == 1 {
		o.counterInvalidPackets.WithLabelValues(dm.DnsTap.Identity).Inc()
	}

	// count the number of queries and replies
	// count the total bytes for queries and replies
	// and then make a histogram for queries and replies packet length observed
	if dm.DNS.Type == dnsutils.DnsQuery {
		o.counterQueries.WithLabelValues(dm.DnsTap.Identity).Inc()
		o.counterReceivedBytes.WithLabelValues(dm.DnsTap.Identity).Add(float64(dm.DNS.Length))
		o.histogramQueriesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(dm.DNS.Length))
	} else {
		o.counterReplies.WithLabelValues(dm.DnsTap.Identity).Inc()
		o.counterSentBytes.WithLabelValues(dm.DnsTap.Identity).Add(float64(dm.DNS.Length))
		o.histogramRepliesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(dm.DNS.Length))
	}

	// make histogram for qname length observed
	o.histogramQnamesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(len(dm.DNS.Qname)))

	// make histogram for latencies observed
	if dm.DnsTap.Latency > 0.0 {
		o.histogramLatencies.WithLabelValues(dm.DnsTap.Identity).Observe(dm.DnsTap.Latency)
	}

	// count number of qtype, rcode, operation, family and protocol for each stream
	o.counterQtypes.WithLabelValues(dm.DnsTap.Identity, dm.DNS.Qtype).Inc()
	o.counterRcodes.WithLabelValues(dm.DnsTap.Identity, dm.DNS.Rcode).Inc()
	o.counterOperations.WithLabelValues(dm.DnsTap.Identity, dm.DnsTap.Operation).Inc()
	o.counterFamilies.WithLabelValues(dm.DnsTap.Identity, dm.NetworkInfo.Family).Inc()
	o.counterProtocols.WithLabelValues(dm.DnsTap.Identity, dm.NetworkInfo.Protocol).Inc()

	// count some specific flags
	if dm.DNS.Flags.TC {
		o.counterFlagsTC.WithLabelValues(dm.DnsTap.Identity).Inc()
	}
	if dm.DNS.Flags.AA {
		o.counterFlagsAA.WithLabelValues(dm.DnsTap.Identity).Inc()
	}
	if dm.DNS.Flags.RA {
		o.counterFlagsRA.WithLabelValues(dm.DnsTap.Identity).Inc()
	}
	if dm.DNS.Flags.AD {
		o.counterFlagsAD.WithLabelValues(dm.DnsTap.Identity).Inc()
	}

	/* count all domains name and top domains */
	if _, exists := o.domains[dm.DnsTap.Identity]; !exists {
		o.domains[dm.DnsTap.Identity] = make(map[string]int)
	}

	if _, exists := o.domains[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
		o.domains[dm.DnsTap.Identity][dm.DNS.Qname] = 1
		o.counterDomains.WithLabelValues(dm.DnsTap.Identity).Inc()
	} else {
		o.domains[dm.DnsTap.Identity][dm.DNS.Qname] += 1
	}

	if _, ok := o.topDomains[dm.DnsTap.Identity]; !ok {
		o.topDomains[dm.DnsTap.Identity] = topmap.NewTopMap(2)
	}
	o.topDomains[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.domains[dm.DnsTap.Identity][dm.DNS.Qname])

	o.gaugeTopDomains.Reset()
	for _, r := range o.topDomains[dm.DnsTap.Identity].Get() {
		o.gaugeTopDomains.WithLabelValues(dm.DnsTap.Identity, r.Name).Set(float64(r.Hit))
	}

	/* record and count all nx domains name and topN*/
	if dm.DNS.Rcode == "NXDOMAIN" {
		if _, exists := o.nxdomains[dm.DnsTap.Identity]; !exists {
			o.nxdomains[dm.DnsTap.Identity] = make(map[string]int)
		}
		if _, exists := o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
			o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname] = 1
			o.counterDomainsNX.WithLabelValues(dm.DnsTap.Identity).Inc()
		} else {
			o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname] += 1
		}

		if _, ok := o.topNxDomains[dm.DnsTap.Identity]; !ok {
			o.topNxDomains[dm.DnsTap.Identity] = topmap.NewTopMap(2)
		}
		o.topNxDomains[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.domains[dm.DnsTap.Identity][dm.DNS.Qname])

		o.gaugeTopNxDomains.Reset()
		for _, r := range o.topNxDomains[dm.DnsTap.Identity].Get() {
			o.gaugeTopNxDomains.WithLabelValues(dm.DnsTap.Identity, r.Name).Set(float64(r.Hit))
		}
	}

	// record all clients and topN
	if _, exists := o.requesters[dm.DnsTap.Identity]; !exists {
		o.requesters[dm.DnsTap.Identity] = make(map[string]int)
	}
	if _, ok := o.requesters[dm.DnsTap.Identity][dm.NetworkInfo.QueryIp]; !ok {
		o.requesters[dm.DnsTap.Identity][dm.NetworkInfo.QueryIp] = 1
		o.counterRequesters.WithLabelValues(dm.DnsTap.Identity).Inc()
	} else {
		o.requesters[dm.DnsTap.Identity][dm.NetworkInfo.QueryIp] += 1
	}

	if _, ok := o.topRequesters[dm.DnsTap.Identity]; !ok {
		o.topRequesters[dm.DnsTap.Identity] = topmap.NewTopMap(2)
	}
	o.topRequesters[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.domains[dm.DnsTap.Identity][dm.DNS.Qname])

	o.gaugeTopRequesters.Reset()
	for _, r := range o.topRequesters[dm.DnsTap.Identity].Get() {
		o.gaugeTopRequesters.WithLabelValues(dm.DnsTap.Identity, r.Name).Set(float64(r.Hit))
	}
}

func (s *Prometheus) ListenAndServe() {
	s.LogInfo("starting prometheus metrics...")

	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.HandlerFor(s.promRegistry, promhttp.HandlerOpts{}))

	var err error
	var listener net.Listener
	addrlisten := s.config.Loggers.Prometheus.ListenIP + ":" + strconv.Itoa(s.config.Loggers.Prometheus.ListenPort)
	// listening with tls enabled ?
	if s.config.Loggers.Prometheus.TlsSupport {
		s.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(s.config.Loggers.Prometheus.CertFile, s.config.Loggers.Prometheus.KeyFile)
		if err != nil {
			s.logger.Fatal("loading certificate failed:", err)
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{cer},
		}

		if s.config.Loggers.Prometheus.TlsMutual {

			// Create a CA certificate pool and add cert.pem to it
			var caCert []byte
			caCert, err = ioutil.ReadFile(s.config.Loggers.Prometheus.CertFile)
			if err != nil {
				s.logger.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			config.ClientCAs = caCertPool
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}

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
	s.LogInfo("is listening on %s", listener.Addr())

	srv := &http.Server{Handler: mux, ErrorLog: s.logger.ErrorLogger()}
	srv.Serve(s.httpserver)

	s.LogInfo("terminated")
	s.done_api <- true
}

func (s *Prometheus) Run() {
	s.LogInfo("running in background...")

	// start http server
	go s.ListenAndServe()

LOOP:
	for {
		dm, opened := <-s.channel
		if !opened {
			s.LogInfo("channel closed")
			break LOOP
		}
		// record the dnstap message
		s.Record(dm)

	}
	s.LogInfo("run terminated")

	// the job is done
	s.done <- true
}
