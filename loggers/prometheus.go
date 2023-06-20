package loggers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-topmap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var metricNameRegex = regexp.MustCompile(`_*[^0-9A-Za-z_]+_*`)

/*
OpenMetrics and the Prometheus exposition format require the metric name
to consist only of alphanumericals and "_", ":" and they must not start
with digits.
*/
func SanitizeMetricName(metricName string) string {
	return metricNameRegex.ReplaceAllString(metricName, "_")
}

type EpsCounters struct {
	Eps             uint64
	EpsMax          uint64
	TotalEvents     uint64
	TotalEventsPrev uint64

	TotalRcodes        map[string]float64
	TotalQtypes        map[string]float64
	TotalIPVersion     map[string]float64
	TotalIPProtocol    map[string]float64
	TotalDnsMessages   float64
	TotalQueries       int
	TotalReplies       int
	TotalBytesSent     int
	TotalBytesReceived int
	TotalBytes         int

	TotalTC         float64
	TotalAA         float64
	TotalRA         float64
	TotalAD         float64
	TotalMalformed  float64
	TotalFragmented float64
	TotalReasembled float64
}

type Prometheus struct {
	doneApi      chan bool
	stopProcess  chan bool
	doneProcess  chan bool
	stopRun      chan bool
	doneRun      chan bool
	httpServer   *http.Server
	netListener  net.Listener
	inputChan    chan dnsutils.DnsMessage
	outputChan   chan dnsutils.DnsMessage
	config       *dnsutils.Config
	logger       *logger.Logger
	promRegistry *prometheus.Registry
	version      string
	sync.Mutex

	requesters map[string]map[string]int
	domains    map[string]map[string]int
	nxdomains  map[string]map[string]int
	sfdomains  map[string]map[string]int
	tlds       map[string]map[string]int
	suspicious map[string]map[string]int
	evicted    map[string]map[string]int

	topDomains    map[string]*topmap.TopMap
	topNxDomains  map[string]*topmap.TopMap
	topSfDomains  map[string]*topmap.TopMap
	topRequesters map[string]*topmap.TopMap
	topTlds       map[string]*topmap.TopMap
	topSuspicious map[string]*topmap.TopMap
	topEvicted    map[string]*topmap.TopMap

	streamsMap map[string]*EpsCounters

	// this one stays as a 'classic' prometheus collector
	gaugeBuildInfo *prometheus.GaugeVec

	gaugeTopDomains    *prometheus.Desc
	gaugeTopNxDomains  *prometheus.Desc
	gaugeTopSfDomains  *prometheus.Desc
	gaugeTopRequesters *prometheus.Desc
	gaugeTopTlds       *prometheus.Desc
	gaugeTopSuspicious *prometheus.Desc
	gaugeTopEvicted    *prometheus.Desc

	gaugeEps    *prometheus.Desc
	gaugeEpsMax *prometheus.Desc

	counterDomains    *prometheus.Desc
	counterDomainsNx  *prometheus.Desc
	counterDomainsSf  *prometheus.Desc
	counterRequesters *prometheus.Desc
	counterTlds       *prometheus.Desc
	counterSuspicious *prometheus.Desc
	counterEvicted    *prometheus.Desc

	counterQtypes      *prometheus.Desc
	counterRcodes      *prometheus.Desc
	counterIPProtocol  *prometheus.Desc
	counterIPVersion   *prometheus.Desc
	counterDnsMessages *prometheus.Desc
	counterDnsQueries  *prometheus.Desc
	counterDnsReplies  *prometheus.Desc

	counterFlagsTC          *prometheus.Desc
	counterFlagsAA          *prometheus.Desc
	counterFlagsRA          *prometheus.Desc
	counterFlagsAD          *prometheus.Desc
	counterFlagsMalformed   *prometheus.Desc
	counterFlagsFragmented  *prometheus.Desc
	counterFlagsReassembled *prometheus.Desc

	totalBytes         *prometheus.Desc
	totalReceivedBytes *prometheus.Desc
	totalSentBytes     *prometheus.Desc

	// Histograms are too expensive to implement internally
	histogramQueriesLength *prometheus.HistogramVec
	histogramRepliesLength *prometheus.HistogramVec
	histogramQnamesLength  *prometheus.HistogramVec
	histogramLatencies     *prometheus.HistogramVec

	name string
}

func NewPrometheus(config *dnsutils.Config, logger *logger.Logger, version string, name string) *Prometheus {
	logger.Info("[%s] logger=prometheus - enabled", name)
	o := &Prometheus{
		doneApi:     make(chan bool),
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		config:      config,
		inputChan:   make(chan dnsutils.DnsMessage, config.Loggers.Prometheus.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DnsMessage, config.Loggers.Prometheus.ChannelBufferSize),
		logger:      logger,
		version:     version,

		promRegistry: prometheus.NewRegistry(),

		requesters: make(map[string]map[string]int),
		domains:    make(map[string]map[string]int),
		nxdomains:  make(map[string]map[string]int),
		sfdomains:  make(map[string]map[string]int),
		tlds:       make(map[string]map[string]int),
		suspicious: make(map[string]map[string]int),
		evicted:    make(map[string]map[string]int),

		topDomains:    make(map[string]*topmap.TopMap),
		topNxDomains:  make(map[string]*topmap.TopMap),
		topSfDomains:  make(map[string]*topmap.TopMap),
		topRequesters: make(map[string]*topmap.TopMap),
		topTlds:       make(map[string]*topmap.TopMap),
		topSuspicious: make(map[string]*topmap.TopMap),
		topEvicted:    make(map[string]*topmap.TopMap),

		streamsMap: make(map[string]*EpsCounters),

		name: name,
	}

	// init prometheus
	o.InitProm()

	// add build version in metrics
	o.gaugeBuildInfo.WithLabelValues(o.version).Set(1)

	// midleware to add basic authentication
	authMiddleware := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok || username != o.config.Loggers.Prometheus.BasicAuthLogin || password != o.config.Loggers.Prometheus.BasicAuthPwd {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, "Unauthorized\n")
				return
			}

			handler.ServeHTTP(w, r)
		})
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(o.promRegistry, promhttp.HandlerOpts{}))

	handler := authMiddleware(mux)

	o.httpServer = &http.Server{}
	if o.config.Loggers.Prometheus.BasicAuthEnabled {
		o.httpServer.Handler = handler
	} else {
		o.httpServer.Handler = mux
	}

	o.httpServer.ErrorLog = o.logger.ErrorLogger()

	return o
}

func (c *Prometheus) GetName() string { return c.name }

func (c *Prometheus) SetLoggers(loggers []dnsutils.Worker) {}

func (o *Prometheus) InitProm() {

	prom_prefix := SanitizeMetricName(o.config.Loggers.Prometheus.PromPrefix)

	o.gaugeBuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_build_info", prom_prefix),
			Help: "Build version",
		},
		[]string{"version"},
	)
	o.promRegistry.MustRegister(o.gaugeBuildInfo)

	// Gauge metrics
	o.gaugeTopDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_domains", prom_prefix),
		"Number of hit per domain topN, partitioned by qname",
		[]string{"stream_id", "domain"}, nil,
	)
	o.gaugeTopNxDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_nxdomains", prom_prefix),
		"Number of hit per nx domain topN, partitioned by qname",
		[]string{"stream_id", "domain"}, nil,
	)

	o.gaugeTopSfDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_sfdomains", prom_prefix),
		"Number of hit per servfail domain topN, partitioned by stream and qname",
		[]string{"stream_id", "domain"}, nil,
	)

	o.gaugeTopRequesters = prometheus.NewDesc(
		fmt.Sprintf("%s_top_requesters", prom_prefix),
		"Number of hit per requester topN, partitioned by client IP",
		[]string{"stream_id", "ip"}, nil,
	)

	o.gaugeTopTlds = prometheus.NewDesc(
		fmt.Sprintf("%s_top_tlds", prom_prefix),
		"Number of hit per tld - topN",
		[]string{"stream_id", "suffix"}, nil,
	)

	o.gaugeTopSuspicious = prometheus.NewDesc(
		fmt.Sprintf("%s_top_suspicious", prom_prefix),
		"Number of hit per suspicious domain - topN",
		[]string{"stream_id", "domain"}, nil,
	)

	o.gaugeTopEvicted = prometheus.NewDesc(
		fmt.Sprintf("%s_top_unanswered", prom_prefix),
		"Number of hit per unanswered domain - topN",
		[]string{"stream_id", "domain"}, nil,
	)

	o.gaugeEps = prometheus.NewDesc(
		fmt.Sprintf("%s_throughput_ops", prom_prefix),
		"Number of ops per second received, partitioned by stream",
		[]string{"stream_id"}, nil,
	)

	o.gaugeEpsMax = prometheus.NewDesc(
		fmt.Sprintf("%s_throughput_ops_max", prom_prefix),
		"Max number of ops per second observed, partitioned by stream",
		[]string{"stream_id"}, nil,
	)

	// Counter metrics
	o.counterDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_domains_total", prom_prefix),
		"The total number of domains per stream identity",
		[]string{"stream_id"}, nil,
	)

	o.counterDomainsNx = prometheus.NewDesc(
		fmt.Sprintf("%s_nxdomains_total", prom_prefix),
		"The total number of unknown domains per stream identity",
		[]string{"stream_id"}, nil,
	)

	o.counterDomainsSf = prometheus.NewDesc(
		fmt.Sprintf("%s_sfdomains_total", prom_prefix),
		"The total number of serverfail domains per stream identity",
		[]string{"stream_id"}, nil,
	)

	o.counterRequesters = prometheus.NewDesc(
		fmt.Sprintf("%s_requesters_total", prom_prefix),
		"The total number of DNS clients per stream identity",
		[]string{"stream_id"}, nil,
	)

	o.counterTlds = prometheus.NewDesc(
		fmt.Sprintf("%s_tlds_total", prom_prefix),
		"The total number of tld per stream identity",
		[]string{"stream_id"}, nil,
	)

	o.counterSuspicious = prometheus.NewDesc(
		fmt.Sprintf("%s_suspicious_total", prom_prefix),
		"The total number of suspicious domain per stream identity",
		[]string{"stream_id"}, nil,
	)

	o.counterEvicted = prometheus.NewDesc(
		fmt.Sprintf("%s_unanswered_total", prom_prefix),
		"The total number of unanswered domains per stream identity",
		[]string{"stream_id"}, nil,
	)

	o.counterQtypes = prometheus.NewDesc(
		fmt.Sprintf("%s_qtypes_total", prom_prefix),
		"Counter of queries per qtypes",
		[]string{
			"stream_id",
			"query_type",
		}, nil,
	)

	o.counterRcodes = prometheus.NewDesc(
		fmt.Sprintf("%s_rcodes_total", prom_prefix),
		"Counter of replies per return codes",
		[]string{
			"stream_id",
			"return_code",
		}, nil,
	)

	o.counterIPProtocol = prometheus.NewDesc(
		fmt.Sprintf("%s_ipprotocol_total", prom_prefix),
		"Counter of packets per IP protocol",
		[]string{
			"stream_id",
			"net_transport",
		}, nil,
	)

	o.counterIPVersion = prometheus.NewDesc(
		fmt.Sprintf("%s_ipversion_total", prom_prefix),
		"Counter of packets per IP version",
		[]string{
			"stream_id",
			"net_family",
		}, nil,
	)

	o.counterDnsMessages = prometheus.NewDesc(
		fmt.Sprintf("%s_dnsmessages_total", prom_prefix),
		"Counter of DNS messages per stream",
		[]string{"stream_id"}, nil,
	)

	o.counterDnsQueries = prometheus.NewDesc(
		fmt.Sprintf("%s_queries_total", prom_prefix),
		"Counter of DNS queries per stream",
		[]string{"stream_id"}, nil,
	)

	o.counterDnsReplies = prometheus.NewDesc(
		fmt.Sprintf("%s_replies_total", prom_prefix),
		"Counter of DNS replies per stream",
		[]string{"stream_id"}, nil,
	)

	o.counterFlagsTC = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_tc_total", prom_prefix),
		"Number of packet with flag TC",
		[]string{"stream_id"}, nil,
	)

	o.counterFlagsAA = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_aa_total", prom_prefix),
		"Number of packet with flag AA",
		[]string{"stream_id"}, nil,
	)

	o.counterFlagsRA = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_ra_total", prom_prefix),
		"Number of packet with flag RA",
		[]string{"stream_id"}, nil,
	)

	o.counterFlagsAD = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_ad_total", prom_prefix),
		"Number of packet with flag AD",
		[]string{"stream_id"}, nil,
	)

	o.counterFlagsMalformed = prometheus.NewDesc(
		fmt.Sprintf("%s_malformed_total", prom_prefix),
		"Number of malformed packets",
		[]string{"stream_id"}, nil,
	)

	o.counterFlagsFragmented = prometheus.NewDesc(
		fmt.Sprintf("%s_fragmented_total", prom_prefix),
		"Number of IP fragmented packets",
		[]string{"stream_id"}, nil,
	)

	o.counterFlagsReassembled = prometheus.NewDesc(
		fmt.Sprintf("%s_reassembled_total", prom_prefix),
		"Number of TCP reassembled packets",
		[]string{"stream_id"}, nil,
	)

	o.totalBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_bytes_total", prom_prefix),
		"The total bytes received and sent",
		[]string{"stream_id"}, nil,
	)

	o.totalReceivedBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_received_bytes_total", prom_prefix),
		"The total bytes received",
		[]string{"stream_id"}, nil,
	)

	o.totalSentBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_sent_bytes_total", prom_prefix),
		"The total bytes sent",
		[]string{"stream_id"}, nil,
	)
	o.histogramQueriesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_queries_size_bytes", prom_prefix),
			Help:    "Size of the queries in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.histogramQueriesLength)

	o.histogramRepliesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_replies_size_bytes", prom_prefix),
			Help:    "Size of the replies in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.histogramRepliesLength)

	o.histogramQnamesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_qnames_size_bytes", prom_prefix),
			Help:    "Size of the qname in bytes.",
			Buckets: []float64{10, 20, 40, 60, 100},
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.histogramQnamesLength)

	o.histogramLatencies = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_latencies", prom_prefix),
			Help:    "Latency between query and reply",
			Buckets: []float64{0.001, 0.010, 0.050, 0.100, 0.5, 1.0},
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.histogramLatencies)

	o.promRegistry.MustRegister(o)
}

func (o *Prometheus) Describe(ch chan<- *prometheus.Desc) {
	// Gauge metrcis
	ch <- o.gaugeTopDomains
	ch <- o.gaugeTopNxDomains
	ch <- o.gaugeTopSfDomains
	ch <- o.gaugeTopRequesters
	ch <- o.gaugeTopTlds
	ch <- o.gaugeTopSuspicious
	ch <- o.gaugeTopEvicted
	ch <- o.gaugeEps
	ch <- o.gaugeEpsMax

	// Counter metrics
	ch <- o.counterDomains
	ch <- o.counterDomainsNx
	ch <- o.counterDomainsSf
	ch <- o.counterRequesters
	ch <- o.counterTlds
	ch <- o.counterSuspicious
	ch <- o.counterEvicted

	ch <- o.counterQtypes
	ch <- o.counterRcodes
	ch <- o.counterIPProtocol
	ch <- o.counterIPVersion
	ch <- o.counterDnsMessages
	ch <- o.counterDnsQueries
	ch <- o.counterDnsReplies

	ch <- o.counterFlagsTC
	ch <- o.counterFlagsAA
	ch <- o.counterFlagsRA
	ch <- o.counterFlagsAD
	ch <- o.counterFlagsMalformed
	ch <- o.counterFlagsFragmented
	ch <- o.counterFlagsReassembled

	ch <- o.totalBytes
	ch <- o.totalReceivedBytes
	ch <- o.totalSentBytes
}

func (o *Prometheus) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.Prometheus.TlsMinVersion) {
		o.logger.Fatal("logger prometheus - invalid tls min version")
	}
}

func (o *Prometheus) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger=prometheus - "+msg, v...)
}

func (o *Prometheus) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger=prometheus - "+msg, v...)
}

func (o *Prometheus) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *Prometheus) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess

	o.LogInfo("stopping http server...")
	o.netListener.Close()
	<-o.doneApi
}

func (o *Prometheus) Record(dm dnsutils.DnsMessage) {
	// record stream identity
	o.Lock()
	defer o.Unlock()
	if _, exists := o.streamsMap[dm.DnsTap.Identity]; !exists {
		o.streamsMap[dm.DnsTap.Identity] = new(EpsCounters)
		o.streamsMap[dm.DnsTap.Identity].TotalEvents = 1
		o.streamsMap[dm.DnsTap.Identity].TotalRcodes = make(map[string]float64)
		o.streamsMap[dm.DnsTap.Identity].TotalQtypes = make(map[string]float64)
		o.streamsMap[dm.DnsTap.Identity].TotalIPVersion = make(map[string]float64)
		o.streamsMap[dm.DnsTap.Identity].TotalIPProtocol = make(map[string]float64)
	} else {
		o.streamsMap[dm.DnsTap.Identity].TotalEvents++
	}

	// count total of bytes and dns messages
	o.streamsMap[dm.DnsTap.Identity].TotalBytes += dm.DNS.Length
	o.streamsMap[dm.DnsTap.Identity].TotalDnsMessages++

	// count number of dns messages per network family (ipv4 or v6)
	if _, exists := o.streamsMap[dm.DnsTap.Identity].TotalIPVersion[dm.NetworkInfo.Family]; !exists {
		o.streamsMap[dm.DnsTap.Identity].TotalIPVersion[dm.NetworkInfo.Family] = 1
	} else {
		o.streamsMap[dm.DnsTap.Identity].TotalIPVersion[dm.NetworkInfo.Family]++
	}

	// count number of dns messages per network protocol (udp, tcp...)
	if _, exists := o.streamsMap[dm.DnsTap.Identity].TotalIPProtocol[dm.NetworkInfo.Protocol]; !exists {
		o.streamsMap[dm.DnsTap.Identity].TotalIPProtocol[dm.NetworkInfo.Protocol] = 1
	} else {
		o.streamsMap[dm.DnsTap.Identity].TotalIPProtocol[dm.NetworkInfo.Protocol]++
	}

	if _, exists := o.streamsMap[dm.DnsTap.Identity].TotalQtypes[dm.DNS.Qtype]; !exists {
		o.streamsMap[dm.DnsTap.Identity].TotalQtypes[dm.DNS.Qtype] = 1
	} else {
		o.streamsMap[dm.DnsTap.Identity].TotalQtypes[dm.DNS.Qtype]++
	}

	if _, exists := o.streamsMap[dm.DnsTap.Identity].TotalRcodes[dm.DNS.Rcode]; !exists {
		o.streamsMap[dm.DnsTap.Identity].TotalRcodes[dm.DNS.Rcode] = 1
	} else {
		o.streamsMap[dm.DnsTap.Identity].TotalRcodes[dm.DNS.Rcode]++
	}

	// count queries and bytes
	if dm.DNS.Type == dnsutils.DnsQuery {
		o.streamsMap[dm.DnsTap.Identity].TotalBytesReceived += dm.DNS.Length
		o.streamsMap[dm.DnsTap.Identity].TotalQueries++

	}

	// count replies and bytes
	if dm.DNS.Type == dnsutils.DnsReply {
		o.streamsMap[dm.DnsTap.Identity].TotalBytesSent += dm.DNS.Length
		o.streamsMap[dm.DnsTap.Identity].TotalReplies++

	}

	// flags
	if dm.DNS.Flags.TC {
		o.streamsMap[dm.DnsTap.Identity].TotalTC++
	}
	if dm.DNS.Flags.AA {
		o.streamsMap[dm.DnsTap.Identity].TotalAA++
	}
	if dm.DNS.Flags.RA {
		o.streamsMap[dm.DnsTap.Identity].TotalRA++
	}
	if dm.DNS.Flags.AD {
		o.streamsMap[dm.DnsTap.Identity].TotalAD++
	}
	if dm.DNS.MalformedPacket {
		o.streamsMap[dm.DnsTap.Identity].TotalMalformed++
	}
	if dm.NetworkInfo.IpDefragmented {
		o.streamsMap[dm.DnsTap.Identity].TotalFragmented++
	}
	if dm.NetworkInfo.TcpReassembled {
		o.streamsMap[dm.DnsTap.Identity].TotalReasembled++
	}

	// count number of dns message per requester ip and top clients
	if _, exists := o.requesters[dm.DnsTap.Identity]; !exists {
		o.requesters[dm.DnsTap.Identity] = make(map[string]int)
	}
	if _, ok := o.requesters[dm.DnsTap.Identity][dm.NetworkInfo.QueryIp]; !ok {
		o.requesters[dm.DnsTap.Identity][dm.NetworkInfo.QueryIp] = 1
	} else {
		o.requesters[dm.DnsTap.Identity][dm.NetworkInfo.QueryIp] += 1
	}
	if _, ok := o.topRequesters[dm.DnsTap.Identity]; !ok {
		o.topRequesters[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
	}
	o.topRequesters[dm.DnsTap.Identity].Record(dm.NetworkInfo.QueryIp, o.requesters[dm.DnsTap.Identity][dm.NetworkInfo.QueryIp])

	// top domains
	switch dm.DNS.Rcode {
	case dnsutils.DNS_RCODE_TIMEOUT:
		if _, exists := o.evicted[dm.DnsTap.Identity]; !exists {
			o.evicted[dm.DnsTap.Identity] = make(map[string]int)
		}
		if _, exists := o.evicted[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
			o.evicted[dm.DnsTap.Identity][dm.DNS.Qname] = 1
		} else {
			o.evicted[dm.DnsTap.Identity][dm.DNS.Qname] += 1
		}

		if _, ok := o.topEvicted[dm.DnsTap.Identity]; !ok {
			o.topEvicted[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
		}
		o.topEvicted[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.evicted[dm.DnsTap.Identity][dm.DNS.Qname])

	case dnsutils.DNS_RCODE_SERVFAIL:
		if _, exists := o.sfdomains[dm.DnsTap.Identity]; !exists {
			o.sfdomains[dm.DnsTap.Identity] = make(map[string]int)
		}
		if _, exists := o.sfdomains[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
			o.sfdomains[dm.DnsTap.Identity][dm.DNS.Qname] = 1
		} else {
			o.sfdomains[dm.DnsTap.Identity][dm.DNS.Qname] += 1
		}

		if _, ok := o.topSfDomains[dm.DnsTap.Identity]; !ok {
			o.topSfDomains[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
		}
		o.topSfDomains[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.sfdomains[dm.DnsTap.Identity][dm.DNS.Qname])

	case dnsutils.DNS_RCODE_NXDOMAIN:
		if _, exists := o.nxdomains[dm.DnsTap.Identity]; !exists {
			o.nxdomains[dm.DnsTap.Identity] = make(map[string]int)
		}
		if _, exists := o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
			o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname] = 1
		} else {
			o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname] += 1
		}

		if _, ok := o.topNxDomains[dm.DnsTap.Identity]; !ok {
			o.topNxDomains[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
		}
		o.topNxDomains[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname])

	default:
		if _, exists := o.domains[dm.DnsTap.Identity]; !exists {
			o.domains[dm.DnsTap.Identity] = make(map[string]int)
		}

		if _, exists := o.domains[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
			o.domains[dm.DnsTap.Identity][dm.DNS.Qname] = 1
		} else {
			o.domains[dm.DnsTap.Identity][dm.DNS.Qname] += 1
		}

		if _, ok := o.topDomains[dm.DnsTap.Identity]; !ok {
			o.topDomains[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
		}
		o.topDomains[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.domains[dm.DnsTap.Identity][dm.DNS.Qname])
	}

	// count and top tld
	if dm.PublicSuffix != nil {
		if dm.PublicSuffix.QnamePublicSuffix != "-" {
			if _, exists := o.tlds[dm.DnsTap.Identity]; !exists {
				o.tlds[dm.DnsTap.Identity] = make(map[string]int)
			}

			if _, exists := o.tlds[dm.DnsTap.Identity][dm.PublicSuffix.QnamePublicSuffix]; !exists {
				o.tlds[dm.DnsTap.Identity][dm.PublicSuffix.QnamePublicSuffix] = 1
			} else {
				o.tlds[dm.DnsTap.Identity][dm.PublicSuffix.QnamePublicSuffix] += 1
			}

			if _, ok := o.topTlds[dm.DnsTap.Identity]; !ok {
				o.topTlds[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
			}
			o.topTlds[dm.DnsTap.Identity].Record(dm.PublicSuffix.QnamePublicSuffix, o.tlds[dm.DnsTap.Identity][dm.PublicSuffix.QnamePublicSuffix])

		}
	}

	// suspicious domains
	if dm.Suspicious != nil {
		if dm.Suspicious.Score > 0.0 {
			if _, exists := o.suspicious[dm.DnsTap.Identity]; !exists {
				o.suspicious[dm.DnsTap.Identity] = make(map[string]int)
			}

			if _, exists := o.suspicious[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
				o.suspicious[dm.DnsTap.Identity][dm.DNS.Qname] = 1
			} else {
				o.suspicious[dm.DnsTap.Identity][dm.DNS.Qname] += 1
			}

			if _, ok := o.topSuspicious[dm.DnsTap.Identity]; !ok {
				o.topSuspicious[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
			}
			o.topSuspicious[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.domains[dm.DnsTap.Identity][dm.DNS.Qname])

		}
	}

	// compute histograms, no more enabled by default to avoid to hurt performance.
	if o.config.Loggers.Prometheus.HistogramMetricsEnabled {
		o.histogramQnamesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(len(dm.DNS.Qname)))

		if dm.DnsTap.Latency > 0.0 {
			o.histogramLatencies.WithLabelValues(dm.DnsTap.Identity).Observe(dm.DnsTap.Latency)
		}

		if dm.DNS.Type == dnsutils.DnsQuery {
			o.histogramQueriesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(dm.DNS.Length))
		} else {
			o.histogramRepliesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(dm.DNS.Length))
		}

	}
}

func (o *Prometheus) Collect(ch chan<- prometheus.Metric) {
	o.Lock()
	defer o.Unlock()
	for stream := range o.streamsMap {
		ch <- prometheus.MustNewConstMetric(o.gaugeEps, prometheus.GaugeValue,
			float64(o.streamsMap[stream].Eps), stream,
		)
		ch <- prometheus.MustNewConstMetric(o.gaugeEpsMax, prometheus.GaugeValue,
			float64(o.streamsMap[stream].EpsMax), stream,
		)

		// Update number of domains
		ch <- prometheus.MustNewConstMetric(o.counterDomains, prometheus.CounterValue,
			float64(len(o.domains[stream])), stream,
		)
		// Count NX domains
		ch <- prometheus.MustNewConstMetric(o.counterDomainsNx, prometheus.CounterValue,
			float64(len(o.nxdomains[stream])), stream,
		)
		// Count SERVFAIL domains
		ch <- prometheus.MustNewConstMetric(o.counterDomainsSf, prometheus.CounterValue,
			float64(len(o.sfdomains[stream])), stream,
		)
		// Requesters counter
		ch <- prometheus.MustNewConstMetric(o.counterRequesters, prometheus.CounterValue,
			float64(len(o.requesters[stream])), stream,
		)

		// Count number of unique TLDs
		ch <- prometheus.MustNewConstMetric(o.counterTlds, prometheus.CounterValue,
			float64(len(o.tlds[stream])), stream,
		)

		// Count number of unique suspicious names
		ch <- prometheus.MustNewConstMetric(o.counterSuspicious, prometheus.CounterValue,
			float64(len(o.suspicious[stream])), stream,
		)

		// Count number of unique unanswered (timedout) names
		ch <- prometheus.MustNewConstMetric(o.counterEvicted, prometheus.CounterValue,
			float64(len(o.evicted[stream])), stream,
		)

		//Update qtypes counter
		for k, v := range o.streamsMap[stream].TotalQtypes {
			ch <- prometheus.MustNewConstMetric(o.counterQtypes, prometheus.CounterValue,
				v, stream, k,
			)
		}

		// Update Return Codes counter
		for k, v := range o.streamsMap[stream].TotalRcodes {
			ch <- prometheus.MustNewConstMetric(o.counterRcodes, prometheus.CounterValue,
				v, stream, k,
			)
		}

		// Update IP protocol counter
		for k, v := range o.streamsMap[stream].TotalIPProtocol {
			ch <- prometheus.MustNewConstMetric(o.counterIPProtocol, prometheus.CounterValue,
				v, stream, k,
			)
		}

		// Update IP version counter
		for k, v := range o.streamsMap[stream].TotalIPVersion {
			ch <- prometheus.MustNewConstMetric(o.counterIPVersion, prometheus.CounterValue,
				v, stream, k,
			)
		}

		// Update global number of dns messages
		ch <- prometheus.MustNewConstMetric(o.counterDnsMessages, prometheus.CounterValue,
			o.streamsMap[stream].TotalDnsMessages, stream)

		// Update number of dns queries
		ch <- prometheus.MustNewConstMetric(o.counterDnsQueries, prometheus.CounterValue,
			float64(o.streamsMap[stream].TotalQueries), stream)

		// Update number of dns replies
		ch <- prometheus.MustNewConstMetric(o.counterDnsReplies, prometheus.CounterValue,
			float64(o.streamsMap[stream].TotalReplies), stream)

		// Update flags
		ch <- prometheus.MustNewConstMetric(o.counterFlagsTC, prometheus.CounterValue,
			o.streamsMap[stream].TotalTC, stream)
		ch <- prometheus.MustNewConstMetric(o.counterFlagsAA, prometheus.CounterValue,
			o.streamsMap[stream].TotalAA, stream)
		ch <- prometheus.MustNewConstMetric(o.counterFlagsRA, prometheus.CounterValue,
			o.streamsMap[stream].TotalRA, stream)
		ch <- prometheus.MustNewConstMetric(o.counterFlagsAD, prometheus.CounterValue,
			o.streamsMap[stream].TotalAD, stream)
		ch <- prometheus.MustNewConstMetric(o.counterFlagsMalformed, prometheus.CounterValue,
			o.streamsMap[stream].TotalMalformed, stream)
		ch <- prometheus.MustNewConstMetric(o.counterFlagsFragmented, prometheus.CounterValue,
			o.streamsMap[stream].TotalFragmented, stream)
		ch <- prometheus.MustNewConstMetric(o.counterFlagsReassembled, prometheus.CounterValue,
			o.streamsMap[stream].TotalReasembled, stream)

		ch <- prometheus.MustNewConstMetric(o.totalBytes,
			prometheus.CounterValue, float64(o.streamsMap[stream].TotalBytes), stream,
		)
		ch <- prometheus.MustNewConstMetric(o.totalReceivedBytes, prometheus.CounterValue,
			float64(o.streamsMap[stream].TotalBytesReceived), stream,
		)
		ch <- prometheus.MustNewConstMetric(o.totalSentBytes, prometheus.CounterValue,
			float64(o.streamsMap[stream].TotalBytesSent), stream)

	}

	for s := range o.topDomains {
		for _, r := range o.topDomains[s].Get() {
			ch <- prometheus.MustNewConstMetric(o.gaugeTopDomains, prometheus.GaugeValue,
				float64(r.Hit), s, r.Name)
		}
	}

	for s := range o.topNxDomains {
		for _, r := range o.topNxDomains[s].Get() {
			ch <- prometheus.MustNewConstMetric(o.gaugeTopNxDomains, prometheus.GaugeValue,
				float64(r.Hit), s, r.Name)
		}
	}

	for s := range o.topSfDomains {
		for _, r := range o.topSfDomains[s].Get() {
			ch <- prometheus.MustNewConstMetric(o.gaugeTopSfDomains, prometheus.GaugeValue,
				float64(r.Hit), s, r.Name)
		}
	}

	for s := range o.topRequesters {
		for _, r := range o.topRequesters[s].Get() {
			ch <- prometheus.MustNewConstMetric(o.gaugeTopRequesters, prometheus.GaugeValue,
				float64(r.Hit), s, r.Name)
		}
	}

	for s := range o.topTlds {
		for _, r := range o.topTlds[s].Get() {
			ch <- prometheus.MustNewConstMetric(o.gaugeTopTlds, prometheus.GaugeValue,
				float64(r.Hit), s, r.Name)
		}
	}

	for s := range o.topSuspicious {
		for _, r := range o.topSuspicious[s].Get() {
			ch <- prometheus.MustNewConstMetric(o.gaugeTopSuspicious, prometheus.GaugeValue,
				float64(r.Hit), s, r.Name)
		}
	}

	for s := range o.topEvicted {
		for _, r := range o.topEvicted[s].Get() {
			ch <- prometheus.MustNewConstMetric(o.gaugeTopEvicted, prometheus.GaugeValue,
				float64(r.Hit), s, r.Name)
		}
	}

}

func (o *Prometheus) ComputeEventsPerSecond() {
	// for each stream compute the number of events per second
	o.Lock()
	defer o.Unlock()
	for stream := range o.streamsMap {

		// compute number of events per second
		if o.streamsMap[stream].TotalEvents > 0 && o.streamsMap[stream].TotalEventsPrev > 0 {
			o.streamsMap[stream].Eps = o.streamsMap[stream].TotalEvents - o.streamsMap[stream].TotalEventsPrev
		}
		o.streamsMap[stream].TotalEventsPrev = o.streamsMap[stream].TotalEvents

		// kept the max number of events per second
		if o.streamsMap[stream].Eps > o.streamsMap[stream].EpsMax {
			o.streamsMap[stream].EpsMax = o.streamsMap[stream].Eps
		}
	}
}

func (s *Prometheus) ListenAndServe() {
	s.LogInfo("starting http server...")

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

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = dnsutils.TLS_VERSION[s.config.Loggers.Prometheus.TlsMinVersion]

		if s.config.Loggers.Prometheus.TlsMutual {

			// Create a CA certificate pool and add cert.pem to it
			var caCert []byte
			caCert, err = os.ReadFile(s.config.Loggers.Prometheus.CertFile)
			if err != nil {
				s.logger.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		listener, err = tls.Listen(dnsutils.SOCKET_TCP, addrlisten, tlsConfig)

	} else {
		// basic listening
		listener, err = net.Listen(dnsutils.SOCKET_TCP, addrlisten)
	}

	// something wrong ?
	if err != nil {
		s.logger.Fatal("http server listening failed:", err)
	}

	s.netListener = listener
	s.LogInfo("is listening on %s", listener.Addr())

	s.httpServer.Serve(s.netListener)

	s.LogInfo("http server terminated")
	s.doneApi <- true
}

func (s *Prometheus) Run() {
	s.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, s.outputChan)
	subprocessors := transformers.NewTransforms(&s.config.OutgoingTransformers, s.logger, s.name, listChannel, 0)

	// start http server
	go s.ListenAndServe()

	// goroutine to process transformed dns messages
	go s.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-s.stopRun:
			// cleanup transformers
			subprocessors.Reset()
			s.doneRun <- true
			break RUN_LOOP
		case dm, opened := <-s.inputChan:
			if !opened {
				s.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDnsMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// send to output channel
			s.outputChan <- dm
		}
	}
	s.LogInfo("run terminated")
}

func (s *Prometheus) Process() {
	// init timer to compute qps
	t1_interval := 1 * time.Second
	t1 := time.NewTimer(t1_interval)

	s.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-s.stopProcess:
			s.doneProcess <- true
			break PROCESS_LOOP
		case dm, opened := <-s.outputChan:
			if !opened {
				s.LogInfo("output channel closed!")
				return
			}

			// record the dnstap message
			s.Record(dm)

		case <-t1.C:
			// compute eps each second
			s.ComputeEventsPerSecond()

			// reset the timer
			t1.Reset(t1_interval)
		}
	}
	s.LogInfo("processing terminated")
}
