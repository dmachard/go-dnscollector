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
}

type Prometheus struct {
	done         chan bool
	done_api     chan bool
	httpServer   *http.Server
	netListener  net.Listener
	channel      chan dnsutils.DnsMessage
	config       *dnsutils.Config
	logger       *logger.Logger
	promRegistry *prometheus.Registry
	version      string

	requesters map[string]map[string]int
	domains    map[string]map[string]int
	nxdomains  map[string]map[string]int
	sfdomains  map[string]map[string]int
	tlds       map[string]map[string]int
	suspicious map[string]map[string]int

	topDomains    map[string]*topmap.TopMap
	topNxDomains  map[string]*topmap.TopMap
	topSfDomains  map[string]*topmap.TopMap
	topRequesters map[string]*topmap.TopMap
	topTlds       map[string]*topmap.TopMap
	topSuspicious map[string]*topmap.TopMap

	requestersUniq map[string]int
	domainsUniq    map[string]int
	nxdomainsUniq  map[string]int
	sfdomainsUniq  map[string]int
	suspiciousUniq map[string]int
	tldsUniq       map[string]int

	streamsMap map[string]*EpsCounters

	gaugeBuildInfo     *prometheus.GaugeVec
	gaugeTopDomains    *prometheus.GaugeVec
	gaugeTopNxDomains  *prometheus.GaugeVec
	gaugeTopSfDomains  *prometheus.GaugeVec
	gaugeTopRequesters *prometheus.GaugeVec
	gaugeTopTlds       *prometheus.GaugeVec
	gaugeTopSuspicious *prometheus.GaugeVec

	gaugeEps    *prometheus.GaugeVec
	gaugeEpsMax *prometheus.GaugeVec

	counterPackets     *prometheus.CounterVec
	totalReceivedBytes *prometheus.CounterVec
	totalSentBytes     *prometheus.CounterVec

	counterDomains    *prometheus.CounterVec
	counterDomainsNx  *prometheus.CounterVec
	counterDomainsSf  *prometheus.CounterVec
	counterRequesters *prometheus.CounterVec
	counterTlds       *prometheus.CounterVec
	counterSuspicious *prometheus.CounterVec

	counterDomainsUniq    *prometheus.CounterVec
	counterDomainsNxUniq  *prometheus.CounterVec
	counterDomainsSfUniq  *prometheus.CounterVec
	counterRequestersUniq *prometheus.CounterVec
	counterTldsUniq       *prometheus.CounterVec
	counterSuspiciousUniq *prometheus.CounterVec

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
		sfdomains:  make(map[string]map[string]int),
		tlds:       make(map[string]map[string]int),
		suspicious: make(map[string]map[string]int),

		topDomains:    make(map[string]*topmap.TopMap),
		topNxDomains:  make(map[string]*topmap.TopMap),
		topSfDomains:  make(map[string]*topmap.TopMap),
		topRequesters: make(map[string]*topmap.TopMap),
		topTlds:       make(map[string]*topmap.TopMap),
		topSuspicious: make(map[string]*topmap.TopMap),

		requestersUniq: make(map[string]int),
		domainsUniq:    make(map[string]int),
		nxdomainsUniq:  make(map[string]int),
		sfdomainsUniq:  make(map[string]int),
		tldsUniq:       make(map[string]int),
		suspiciousUniq: make(map[string]int),

		streamsMap: make(map[string]*EpsCounters),

		name: name,
	}

	// init prometheus
	o.InitProm()

	// add build version in metrics
	o.gaugeBuildInfo.WithLabelValues(o.version).Set(1)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(o.promRegistry, promhttp.HandlerOpts{}))
	o.httpServer = &http.Server{Handler: mux, ErrorLog: o.logger.ErrorLogger()}

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

	o.gaugeTopTlds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_tlds", prom_prefix),
			Help: "Number of hit per tld - topN",
		},
		[]string{"stream_id", "domain"},
	)
	o.promRegistry.MustRegister(o.gaugeTopTlds)

	o.gaugeTopSuspicious = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_suspicious", prom_prefix),
			Help: "Number of hit per suspicious domain - topN",
		},
		[]string{"stream_id", "domain"},
	)
	o.promRegistry.MustRegister(o.gaugeTopSuspicious)

	o.gaugeTopDomains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_domains", prom_prefix),
			Help: "Number of hit per domain topN, partitioned by qname",
		},
		[]string{"stream_id", "domain"},
	)
	o.promRegistry.MustRegister(o.gaugeTopDomains)

	o.gaugeTopNxDomains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_nxdomains", prom_prefix),
			Help: "Number of hit per nx domain topN, partitioned by qname",
		},
		[]string{"stream_id", "domain"},
	)
	o.promRegistry.MustRegister(o.gaugeTopNxDomains)

	o.gaugeTopSfDomains = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_sfdomains", prom_prefix),
			Help: "Number of hit per servfail domain topN, partitioned by qname",
		},
		[]string{"stream_id", "domain"},
	)
	o.promRegistry.MustRegister(o.gaugeTopSfDomains)

	o.gaugeTopRequesters = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_top_requesters", prom_prefix),
			Help: "Number of hit per requester topN, partitioned by client IP",
		},
		[]string{"stream_id", "ip"},
	)
	o.promRegistry.MustRegister(o.gaugeTopRequesters)

	o.gaugeEps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_throughput_ops", prom_prefix),
			Help: "Number of ops per second received, partitioned by qname",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.gaugeEps)

	o.gaugeEpsMax = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_throughput_ops_max", prom_prefix),
			Help: "Max number of ops per second observed, partitioned by qname",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.gaugeEpsMax)

	o.counterPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_packets_total", prom_prefix),
			Help: "Counter of packets",
		},
		[]string{
			"stream_id",
			"net_family",
			"net_transport",
			"op_name",
			"op_code",
			"return_code",
			"query_type",
			"flag_qr",
			"flag_tc",
			"flag_aa",
			"flag_ra",
			"flag_ad",
			"pkt_err"},
	)
	o.promRegistry.MustRegister(o.counterPackets)

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

	o.totalReceivedBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_received_bytes_total", prom_prefix),
			Help: "The total bytes received",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.totalReceivedBytes)

	o.totalSentBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_sent_bytes_total", prom_prefix),
			Help: "The total bytes sent",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.totalSentBytes)

	o.counterDomains = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_domains_total", prom_prefix),
			Help: "The total number of domains per stream identity",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.counterDomains)

	o.counterTlds = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_tlds_total", prom_prefix),
			Help: "The total number of tld per stream identity",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.counterTlds)

	o.counterSuspicious = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_suspicious_total", prom_prefix),
			Help: "The total number of suspicious domain per stream identity",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.counterSuspicious)

	o.counterDomainsNx = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_nxdomains_total", prom_prefix),
			Help: "The total number of unknown domains per stream identity",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.counterDomainsNx)

	o.counterDomainsSf = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_sfdomains_total", prom_prefix),
			Help: "The total number of unreachable domains per stream identity",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.counterDomainsSf)

	o.counterRequesters = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_requesters_total", prom_prefix),
			Help: "The total number of DNS clients per stream identity",
		},
		[]string{"stream_id"},
	)
	o.promRegistry.MustRegister(o.counterRequesters)

	o.counterTldsUniq = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_tlds_uniq_total", prom_prefix),
			Help: "The total number of uniq TLD",
		},
		[]string{},
	)
	o.promRegistry.MustRegister(o.counterTldsUniq)

	o.counterSuspiciousUniq = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_suspicious_uniq_total", prom_prefix),
			Help: "The total number of uniq suspicious domain",
		},
		[]string{},
	)
	o.promRegistry.MustRegister(o.counterSuspiciousUniq)

	o.counterDomainsUniq = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_domains_uniq_total", prom_prefix),
			Help: "The total number of uniq domains",
		},
		[]string{},
	)
	o.promRegistry.MustRegister(o.counterDomainsUniq)

	o.counterDomainsNxUniq = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_domains_nx_uniq_total", prom_prefix),
			Help: "The total number of uniq unknown domains",
		},
		[]string{},
	)
	o.promRegistry.MustRegister(o.counterDomainsNxUniq)

	o.counterDomainsSfUniq = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_domains_sf_uniq_total", prom_prefix),
			Help: "The total number of uniq unreachable domains",
		},
		[]string{},
	)
	o.promRegistry.MustRegister(o.counterDomainsSfUniq)

	o.counterRequestersUniq = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_requesters_uniq_total", prom_prefix),
			Help: "The total number of uniq DNS clients",
		},
		[]string{},
	)
	o.promRegistry.MustRegister(o.counterRequestersUniq)
}

func (o *Prometheus) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.Prometheus.TlsMinVersion) {
		o.logger.Fatal("logger prometheus - invalid tls min version")
	}
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
	o.netListener.Close()

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

func (o *Prometheus) Record(dm dnsutils.DnsMessage) {
	// record stream identity
	if _, exists := o.streamsMap[dm.DnsTap.Identity]; !exists {
		o.streamsMap[dm.DnsTap.Identity] = new(EpsCounters)
		o.streamsMap[dm.DnsTap.Identity].TotalEvents = 1
	} else {
		o.streamsMap[dm.DnsTap.Identity].TotalEvents += 1
	}

	// count number of logs according to the stream name
	//o.counterPackets.WithLabelValues(dm.DnsTap.Identity).Inc()
	o.counterPackets.WithLabelValues(
		dm.DnsTap.Identity,
		dm.NetworkInfo.Family,
		dm.NetworkInfo.Protocol,
		dm.DnsTap.Operation,
		strconv.Itoa(dm.DNS.Opcode),
		dm.DNS.Rcode,
		dm.DNS.Qtype,
		dm.DNS.Type,
		strconv.FormatBool(dm.DNS.Flags.TC),
		strconv.FormatBool(dm.DNS.Flags.AA),
		strconv.FormatBool(dm.DNS.Flags.RA),
		strconv.FormatBool(dm.DNS.Flags.AD),
		strconv.FormatBool(dm.DNS.MalformedPacket),
	).Inc()

	// count the number of queries and replies
	// count the total bytes for queries and replies
	// and then make a histogram for queries and replies packet length observed
	if dm.DNS.Type == dnsutils.DnsQuery {
		o.totalReceivedBytes.WithLabelValues(dm.DnsTap.Identity).Add(float64(dm.DNS.Length))
		o.histogramQueriesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(dm.DNS.Length))
	} else {
		o.totalSentBytes.WithLabelValues(dm.DnsTap.Identity).Add(float64(dm.DNS.Length))
		o.histogramRepliesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(dm.DNS.Length))
	}

	// make histogram for qname length observed
	o.histogramQnamesLength.WithLabelValues(dm.DnsTap.Identity).Observe(float64(len(dm.DNS.Qname)))

	// make histogram for latencies observed
	if dm.DnsTap.Latency > 0.0 {
		o.histogramLatencies.WithLabelValues(dm.DnsTap.Identity).Observe(dm.DnsTap.Latency)
	}

	/* count all domains name and top domains */
	if dm.DNS.Rcode == dnsutils.DNS_RCODE_SERVFAIL {
		/* record and count all unreachable domains name and topN*/
		if _, exists := o.sfdomainsUniq[dm.DNS.Qname]; !exists {
			o.sfdomainsUniq[dm.DNS.Qname] = 1
			o.counterDomainsSfUniq.WithLabelValues().Inc()
		} else {
			o.sfdomainsUniq[dm.DNS.Qname] += 1
		}

		if _, exists := o.sfdomains[dm.DnsTap.Identity]; !exists {
			o.sfdomains[dm.DnsTap.Identity] = make(map[string]int)
		}
		if _, exists := o.sfdomains[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
			o.sfdomains[dm.DnsTap.Identity][dm.DNS.Qname] = 1
			o.counterDomainsSf.WithLabelValues(dm.DnsTap.Identity).Inc()
		} else {
			o.sfdomains[dm.DnsTap.Identity][dm.DNS.Qname] += 1
		}

		if _, ok := o.topSfDomains[dm.DnsTap.Identity]; !ok {
			o.topSfDomains[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
		}
		o.topSfDomains[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.sfdomains[dm.DnsTap.Identity][dm.DNS.Qname])

		o.gaugeTopSfDomains.Reset()
		for s := range o.topSfDomains {
			for _, r := range o.topSfDomains[s].Get() {
				o.gaugeTopSfDomains.WithLabelValues(s, r.Name).Set(float64(r.Hit))
			}
		}
	} else if dm.DNS.Rcode == dnsutils.DNS_RCODE_NXDOMAIN {
		/* record and count all nx domains name and topN*/
		if _, exists := o.nxdomainsUniq[dm.DNS.Qname]; !exists {
			o.nxdomainsUniq[dm.DNS.Qname] = 1
			o.counterDomainsNxUniq.WithLabelValues().Inc()
		} else {
			o.nxdomainsUniq[dm.DNS.Qname] += 1
		}

		if _, exists := o.nxdomains[dm.DnsTap.Identity]; !exists {
			o.nxdomains[dm.DnsTap.Identity] = make(map[string]int)
		}
		if _, exists := o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
			o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname] = 1
			o.counterDomainsNx.WithLabelValues(dm.DnsTap.Identity).Inc()
		} else {
			o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname] += 1
		}

		if _, ok := o.topNxDomains[dm.DnsTap.Identity]; !ok {
			o.topNxDomains[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
		}
		o.topNxDomains[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.nxdomains[dm.DnsTap.Identity][dm.DNS.Qname])

		o.gaugeTopNxDomains.Reset()
		for s := range o.topNxDomains {
			for _, r := range o.topNxDomains[s].Get() {
				o.gaugeTopNxDomains.WithLabelValues(s, r.Name).Set(float64(r.Hit))
			}
		}
	} else {
		if _, exists := o.domainsUniq[dm.DNS.Qname]; !exists {
			o.domainsUniq[dm.DNS.Qname] = 1
			o.counterDomainsUniq.WithLabelValues().Inc()
		} else {
			o.domainsUniq[dm.DNS.Qname] += 1
		}

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
			o.topDomains[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
		}
		o.topDomains[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.domains[dm.DnsTap.Identity][dm.DNS.Qname])

		o.gaugeTopDomains.Reset()
		for s := range o.topDomains {
			for _, r := range o.topDomains[s].Get() {
				o.gaugeTopDomains.WithLabelValues(s, r.Name).Set(float64(r.Hit))
			}
		}
	}

	// count and top tld
	if _, exists := o.tldsUniq[dm.DNS.QnamePublicSuffix]; !exists {
		o.tldsUniq[dm.DNS.QnamePublicSuffix] = 1
		o.counterTldsUniq.WithLabelValues().Inc()
	} else {
		o.tldsUniq[dm.DNS.QnamePublicSuffix] += 1
	}

	if _, exists := o.tlds[dm.DnsTap.Identity]; !exists {
		o.tlds[dm.DnsTap.Identity] = make(map[string]int)
	}

	if _, exists := o.tlds[dm.DnsTap.Identity][dm.DNS.QnamePublicSuffix]; !exists {
		o.tlds[dm.DnsTap.Identity][dm.DNS.Qname] = 1
		o.counterTlds.WithLabelValues(dm.DnsTap.Identity).Inc()
	} else {
		o.tlds[dm.DnsTap.Identity][dm.DNS.QnamePublicSuffix] += 1
	}

	if _, ok := o.topTlds[dm.DnsTap.Identity]; !ok {
		o.topTlds[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
	}
	o.topTlds[dm.DnsTap.Identity].Record(dm.DNS.QnamePublicSuffix, o.domains[dm.DnsTap.Identity][dm.DNS.QnamePublicSuffix])

	o.gaugeTopTlds.Reset()
	for s := range o.topTlds {
		for _, r := range o.topTlds[s].Get() {
			o.gaugeTopTlds.WithLabelValues(s, r.Name).Set(float64(r.Hit))
		}
	}

	// suspicious domains
	if dm.Suspicious.Score > 0.0 {
		if _, exists := o.suspiciousUniq[dm.DNS.Qname]; !exists {
			o.suspiciousUniq[dm.DNS.Qname] = 1
			o.counterSuspiciousUniq.WithLabelValues().Inc()
		} else {
			o.suspiciousUniq[dm.DNS.Qname] += 1
		}

		if _, exists := o.suspicious[dm.DnsTap.Identity]; !exists {
			o.suspicious[dm.DnsTap.Identity] = make(map[string]int)
		}

		if _, exists := o.suspicious[dm.DnsTap.Identity][dm.DNS.Qname]; !exists {
			o.suspicious[dm.DnsTap.Identity][dm.DNS.Qname] = 1
			o.counterSuspicious.WithLabelValues(dm.DnsTap.Identity).Inc()
		} else {
			o.suspicious[dm.DnsTap.Identity][dm.DNS.Qname] += 1
		}

		if _, ok := o.topSuspicious[dm.DnsTap.Identity]; !ok {
			o.topSuspicious[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
		}
		o.topSuspicious[dm.DnsTap.Identity].Record(dm.DNS.Qname, o.domains[dm.DnsTap.Identity][dm.DNS.Qname])

		o.gaugeTopSuspicious.Reset()
		for s := range o.topSuspicious {
			for _, r := range o.topSuspicious[s].Get() {
				o.gaugeTopSuspicious.WithLabelValues(s, r.Name).Set(float64(r.Hit))
			}
		}
	}

	// record all clients and topN
	if _, ok := o.requestersUniq[dm.NetworkInfo.QueryIp]; !ok {
		o.requestersUniq[dm.NetworkInfo.QueryIp] = 1
		o.counterRequestersUniq.WithLabelValues().Inc()
	} else {
		o.requestersUniq[dm.NetworkInfo.QueryIp] += 1
	}

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
		o.topRequesters[dm.DnsTap.Identity] = topmap.NewTopMap(o.config.Loggers.Prometheus.TopN)
	}
	o.topRequesters[dm.DnsTap.Identity].Record(dm.NetworkInfo.QueryIp, o.requesters[dm.DnsTap.Identity][dm.NetworkInfo.QueryIp])

	o.gaugeTopRequesters.Reset()
	for s := range o.topRequesters {
		for _, r := range o.topRequesters[s].Get() {
			o.gaugeTopRequesters.WithLabelValues(s, r.Name).Set(float64(r.Hit))
		}
	}
}

func (o *Prometheus) ComputeEps() {
	// for each stream compute the number of events per second
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

		o.gaugeEps.WithLabelValues(stream).Set(float64(o.streamsMap[stream].Eps))
		o.gaugeEpsMax.WithLabelValues(stream).Set(float64(o.streamsMap[stream].EpsMax))
	}
}

func (s *Prometheus) ListenAndServe() {
	s.LogInfo("starting prometheus metrics...")

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
		s.logger.Fatal("listening failed:", err)
	}

	s.netListener = listener
	s.LogInfo("is listening on %s", listener.Addr())

	s.httpServer.Serve(s.netListener)

	s.LogInfo("terminated")
	s.done_api <- true
}

func (s *Prometheus) Run() {
	s.LogInfo("running in background...")

	// prepare transforms
	subprocessors := transformers.NewTransforms(&s.config.OutgoingTransformers, s.logger, s.name)

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

			// apply tranforms
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// record the dnstap message
			s.Record(dm)

		case <-t1.C:
			// compute eps each second
			s.ComputeEps()

			// reset the timer
			t1.Reset(t1_interval)
		}

	}
	s.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	s.done <- true
}
