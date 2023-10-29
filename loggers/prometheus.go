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
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	// _ "net/http/pprof"
)

var metricNameRegex = regexp.MustCompile(`_*[^0-9A-Za-z_]+_*`)

/*
This is the list of available label values selectors.
Configuration may specifiy a list of lables to use for metrics.
Any label in this catalogueSelectors can be specidied in config (prometheus-labels stanza)
*/
var catalogueSelectors map[string]func(*dnsutils.DnsMessage) string = map[string]func(*dnsutils.DnsMessage) string{
	"stream_id": GetStreamID,
	"resolver":  GetResolverIP,
}

/*
OpenMetrics and the Prometheus exposition format require the metric name
to consist only of alphanumericals and "_", ":" and they must not start
with digits.
*/
func SanitizeMetricName(metricName string) string {
	return metricNameRegex.ReplaceAllString(metricName, "_")
}

/*
EpsCounters (Events Per Second) - is a set of metrics we calculate on per-second basis.
For others we rely on averaging by collector
*/
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

type PrometheusCountersCatalogue interface {
	// Prometheus logger encapsulates stats counters (PrometheusCounterSet) inside
	// PromCounterCatalogueContainer's. For each label the logger creates a nested level
	// of containers.
	// Containers and CounterSets must implemnent PrometheusCountersCatalogue interface
	// to allow fetching a CounterSet by the list of metric/values by fetching values from
	// the DNS message it logs.
	// There is a schematic sample layout when there are 2 labels considered at the end of this file
	GetCountersSet(*dnsutils.DnsMessage) PrometheusCountersCatalogue
}

// This type represents a set of counters for a unique set of label name=value pairs.
// By default, we create a set per setream_id for backward compatibility
// However, we can allow slicing and dicing data using more dimentions.
// Each CounterSet is registered with Prometheus collection independently (wrapping label values)
type PrometheusCountersSet struct {
	prom *Prometheus

	// Counters
	requesters map[string]int // Requests number made by a specific requestor
	domains    map[string]int // Requests number made to find out about a specific domain
	nxdomains  map[string]int // Requests number ended up in NXDOMAIN
	sfdomains  map[string]int // Requests number ended up in SERVFAIL
	tlds       map[string]int // Requests number for a specific TLD
	suspicious map[string]int // Requests number for a specific name that looked suspicious
	evicted    map[string]int // Requests number for a specific name that timed out

	epsCounters   EpsCounters
	topRequesters *topmap.TopMap
	topEvicted    *topmap.TopMap
	topSfDomains  *topmap.TopMap
	topDomains    *topmap.TopMap
	topNxDomains  *topmap.TopMap
	topTlds       *topmap.TopMap
	topSuspicious *topmap.TopMap

	labels     prometheus.Labels // Do we really need to keep that map outside of registration?
	sync.Mutex                   // Each PrometheusCountersSet locks independently
}

// PromCounterCatalogueContainer is the implementation of PrometheusCountersCatalogue interface
// That maps a single label into other Containers or CounterSet
// The 'chain' of nested Containers keep track of label_names requested by the config
// to figure out whether nested Container should be created, or, if all labels but the last one
// already considered at the upper levels, it is time to create individual CounterSet
type PromCounterCatalogueContainer struct {
	prom *Prometheus

	// label_names - is a list of label *names* for PromCounterCatalogueContainer's in stats
	// map to use to get proper selectors.
	// The topmost instance of PromCounterCatalogueContainer has the full list of all names to
	// consider (the one provided by the config). Whenver it needs to create a new item in
	// it's stats map, it suplies label_names[1:] to the constructor for the lower level
	// container to get the selector for the next level
	label_names []string // This is list of label names for nested containers

	// This is the unique set of label-value pairs for this catalogue element.
	// The topmost Catalog has it empty, when it creates a new entry it provides the pair of
	// label_names[0]->selector(message) to the constructor. Lower levels get these pair
	// collected. Ultimately, when all label names in label_names is exausted, Catalogue creates
	// an instance of newPrometheusCounterSet and provides it with labels map to properly wrap
	// in Prometheus registry.
	// The goal is to separate label/values pairs construction and individual counters collection
	labels map[string]string // This is the set of label=value pairs we collected to this level
	stats  map[string]PrometheusCountersCatalogue

	// selector is a function that obtains a value for a label considering DNS Message data
	// in most cases - just a field of that message
	selector func(*dnsutils.DnsMessage) string

	sync.RWMutex
}

/*
Selectors
*/
func GetStreamID(dm *dnsutils.DnsMessage) string {
	return dm.DnsTap.Identity
}

func GetResolverIP(dm *dnsutils.DnsMessage) string {
	return dm.NetworkInfo.ResponseIp
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
	configChan   chan *dnsutils.Config
	logger       *logger.Logger
	promRegistry *prometheus.Registry

	sync.Mutex
	catalogueLabels []string
	counters        *PromCounterCatalogueContainer

	// All metrics use these descriptions when regestering
	gaugeTopDomains    *prometheus.Desc
	gaugeTopNxDomains  *prometheus.Desc
	gaugeTopSfDomains  *prometheus.Desc
	gaugeTopRequesters *prometheus.Desc
	gaugeTopTlds       *prometheus.Desc
	gaugeTopSuspicious *prometheus.Desc
	gaugeTopEvicted    *prometheus.Desc

	counterDomains    *prometheus.Desc
	counterDomainsNx  *prometheus.Desc
	counterDomainsSf  *prometheus.Desc
	counterRequesters *prometheus.Desc
	counterTlds       *prometheus.Desc
	counterSuspicious *prometheus.Desc
	counterEvicted    *prometheus.Desc

	gaugeEps    *prometheus.Desc
	gaugeEpsMax *prometheus.Desc

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

	// Histograms are heavy and expensive, turned off
	// by default in configuration
	histogramQueriesLength *prometheus.HistogramVec
	histogramRepliesLength *prometheus.HistogramVec
	histogramQnamesLength  *prometheus.HistogramVec
	histogramLatencies     *prometheus.HistogramVec

	name string
}

func newPrometheusCounterSet(p *Prometheus, labels prometheus.Labels) *PrometheusCountersSet {
	pcs := &PrometheusCountersSet{
		prom:       p,
		labels:     labels,
		requesters: make(map[string]int),
		domains:    make(map[string]int),
		nxdomains:  make(map[string]int),
		sfdomains:  make(map[string]int),
		tlds:       make(map[string]int),
		suspicious: make(map[string]int),
		evicted:    make(map[string]int),

		epsCounters: EpsCounters{
			TotalRcodes:     make(map[string]float64),
			TotalQtypes:     make(map[string]float64),
			TotalIPVersion:  make(map[string]float64),
			TotalIPProtocol: make(map[string]float64),
		},

		topRequesters: topmap.NewTopMap(p.config.Loggers.Prometheus.TopN),
		topEvicted:    topmap.NewTopMap(p.config.Loggers.Prometheus.TopN),
		topSfDomains:  topmap.NewTopMap(p.config.Loggers.Prometheus.TopN),
		topDomains:    topmap.NewTopMap(p.config.Loggers.Prometheus.TopN),
		topNxDomains:  topmap.NewTopMap(p.config.Loggers.Prometheus.TopN),
		topTlds:       topmap.NewTopMap(p.config.Loggers.Prometheus.TopN),
		topSuspicious: topmap.NewTopMap(p.config.Loggers.Prometheus.TopN),
	}

	prometheus.WrapRegistererWith(labels, p.promRegistry).MustRegister(pcs)
	return pcs
}

func (c *PrometheusCountersSet) GetCountersSet(dm *dnsutils.DnsMessage) PrometheusCountersCatalogue {
	return c
}

// each CounterSet has the same list of timeseries descriptors,
// so it uses descriptros from the Prometheus instance the set belongs to.
func (c *PrometheusCountersSet) Describe(ch chan<- *prometheus.Desc) {
	// Gauge metrcis
	c.Lock()
	defer c.Unlock()
	ch <- c.prom.gaugeTopDomains
	ch <- c.prom.gaugeTopNxDomains
	ch <- c.prom.gaugeTopSfDomains
	ch <- c.prom.gaugeTopRequesters
	ch <- c.prom.gaugeTopTlds
	ch <- c.prom.gaugeTopSuspicious
	ch <- c.prom.gaugeTopEvicted

	// Counter metrics
	ch <- c.prom.counterDomains
	ch <- c.prom.counterDomainsNx
	ch <- c.prom.counterDomainsSf
	ch <- c.prom.counterRequesters
	ch <- c.prom.counterTlds
	ch <- c.prom.counterSuspicious
	ch <- c.prom.counterEvicted

	ch <- c.prom.gaugeEps
	ch <- c.prom.gaugeEpsMax

	ch <- c.prom.counterQtypes
	ch <- c.prom.counterRcodes
	ch <- c.prom.counterIPProtocol
	ch <- c.prom.counterIPVersion
	ch <- c.prom.counterDnsMessages
	ch <- c.prom.counterDnsQueries
	ch <- c.prom.counterDnsReplies

	ch <- c.prom.counterFlagsTC
	ch <- c.prom.counterFlagsAA
	ch <- c.prom.counterFlagsRA
	ch <- c.prom.counterFlagsAD
	ch <- c.prom.counterFlagsMalformed
	ch <- c.prom.counterFlagsFragmented
	ch <- c.prom.counterFlagsReassembled

	ch <- c.prom.totalBytes
	ch <- c.prom.totalReceivedBytes
	ch <- c.prom.totalSentBytes
}

// Updates all counters for a specific set of labelName=labelValue
func (c *PrometheusCountersSet) Record(dm dnsutils.DnsMessage) {
	c.Lock()
	defer c.Unlock()
	// count number of dns message per requester ip and top clients
	if _, exists := c.requesters[dm.NetworkInfo.QueryIp]; !exists {
		c.requesters[dm.NetworkInfo.QueryIp] = 1
	} else {
		c.requesters[dm.NetworkInfo.QueryIp] += 1
	}
	c.topRequesters.Record(dm.NetworkInfo.QueryIp, c.requesters[dm.NetworkInfo.QueryIp])

	// top domains
	switch dm.DNS.Rcode {
	case dnsutils.DNS_RCODE_TIMEOUT:
		if _, exists := c.evicted[dm.DNS.Qname]; !exists {
			c.evicted[dm.DNS.Qname] = 1
		} else {
			c.evicted[dm.DNS.Qname] += 1
		}
		c.topEvicted.Record(dm.DNS.Qname, c.evicted[dm.DNS.Qname])

	case dnsutils.DNS_RCODE_SERVFAIL:
		if _, exists := c.sfdomains[dm.DNS.Qname]; !exists {
			c.sfdomains[dm.DNS.Qname] = 1
		} else {
			c.sfdomains[dm.DNS.Qname] += 1
		}

		c.topSfDomains.Record(dm.DNS.Qname, c.sfdomains[dm.DNS.Qname])

	case dnsutils.DNS_RCODE_NXDOMAIN:
		if _, exists := c.nxdomains[dm.DNS.Qname]; !exists {
			c.nxdomains[dm.DNS.Qname] = 1
		} else {
			c.nxdomains[dm.DNS.Qname] += 1
		}
		c.topNxDomains.Record(dm.DNS.Qname, c.nxdomains[dm.DNS.Qname])

	default:
		if _, exists := c.domains[dm.DNS.Qname]; !exists {
			c.domains[dm.DNS.Qname] = 1
		} else {
			c.domains[dm.DNS.Qname] += 1
		}
		c.topDomains.Record(dm.DNS.Qname, c.domains[dm.DNS.Qname])
	}

	// count and top tld
	if dm.PublicSuffix != nil {
		if dm.PublicSuffix.QnamePublicSuffix != "-" {
			if _, exists := c.tlds[dm.PublicSuffix.QnamePublicSuffix]; !exists {
				c.tlds[dm.PublicSuffix.QnamePublicSuffix] = 1
			} else {
				c.tlds[dm.PublicSuffix.QnamePublicSuffix] += 1
			}
			c.topTlds.Record(dm.PublicSuffix.QnamePublicSuffix, c.tlds[dm.PublicSuffix.QnamePublicSuffix])
		}
	}

	// suspicious domains
	if dm.Suspicious != nil {
		if dm.Suspicious.Score > 0.0 {
			if _, exists := c.suspicious[dm.DNS.Qname]; !exists {
				c.suspicious[dm.DNS.Qname] = 1
			} else {
				c.suspicious[dm.DNS.Qname] += 1
			}

			c.topSuspicious.Record(dm.DNS.Qname, c.domains[dm.DNS.Qname])
		}
	}
	// compute histograms, no more enabled by default to avoid to hurt performance.
	if c.prom.config.Loggers.Prometheus.HistogramMetricsEnabled {
		c.prom.histogramQnamesLength.With(c.labels).Observe(float64(len(dm.DNS.Qname)))

		if dm.DnsTap.Latency > 0.0 {
			c.prom.histogramLatencies.With(c.labels).Observe(dm.DnsTap.Latency)
		}

		if dm.DNS.Type == dnsutils.DnsQuery {
			c.prom.histogramQueriesLength.With(c.labels).Observe(float64(dm.DNS.Length))
		} else {
			c.prom.histogramRepliesLength.With(c.labels).Observe(float64(dm.DNS.Length))
		}
	}

	// Record EPS related data
	c.epsCounters.TotalEvents++
	c.epsCounters.TotalBytes += dm.DNS.Length
	c.epsCounters.TotalDnsMessages++

	if _, exists := c.epsCounters.TotalIPVersion[dm.NetworkInfo.Family]; !exists {
		c.epsCounters.TotalIPVersion[dm.NetworkInfo.Family] = 1
	} else {
		c.epsCounters.TotalIPVersion[dm.NetworkInfo.Family]++
	}

	if _, exists := c.epsCounters.TotalIPProtocol[dm.NetworkInfo.Protocol]; !exists {
		c.epsCounters.TotalIPProtocol[dm.NetworkInfo.Protocol] = 1
	} else {
		c.epsCounters.TotalIPProtocol[dm.NetworkInfo.Protocol]++
	}

	if _, exists := c.epsCounters.TotalQtypes[dm.DNS.Qtype]; !exists {
		c.epsCounters.TotalQtypes[dm.DNS.Qtype] = 1
	} else {
		c.epsCounters.TotalQtypes[dm.DNS.Qtype]++
	}

	if _, exists := c.epsCounters.TotalRcodes[dm.DNS.Rcode]; !exists {
		c.epsCounters.TotalRcodes[dm.DNS.Rcode] = 1
	} else {
		c.epsCounters.TotalRcodes[dm.DNS.Rcode]++
	}

	if dm.DNS.Type == dnsutils.DnsQuery {
		c.epsCounters.TotalBytesReceived += dm.DNS.Length
		c.epsCounters.TotalQueries++
	}
	if dm.DNS.Type == dnsutils.DnsReply {
		c.epsCounters.TotalBytesSent += dm.DNS.Length
		c.epsCounters.TotalReplies++
	}

	// flags
	if dm.DNS.Flags.TC {
		c.epsCounters.TotalTC++
	}
	if dm.DNS.Flags.AA {
		c.epsCounters.TotalAA++
	}
	if dm.DNS.Flags.RA {
		c.epsCounters.TotalRA++
	}
	if dm.DNS.Flags.AD {
		c.epsCounters.TotalAD++
	}
	if dm.DNS.MalformedPacket {
		c.epsCounters.TotalMalformed++
	}
	if dm.NetworkInfo.IpDefragmented {
		c.epsCounters.TotalFragmented++
	}
	if dm.NetworkInfo.TcpReassembled {
		c.epsCounters.TotalReasembled++
	}

}

func (o *PrometheusCountersSet) Collect(ch chan<- prometheus.Metric) {
	o.Lock()
	defer o.Unlock()
	// Update number of domains
	ch <- prometheus.MustNewConstMetric(o.prom.counterDomains, prometheus.CounterValue,
		float64(len(o.domains)),
	)
	// Count NX domains
	ch <- prometheus.MustNewConstMetric(o.prom.counterDomainsNx, prometheus.CounterValue,
		float64(len(o.nxdomains)),
	)
	// Count SERVFAIL domains
	ch <- prometheus.MustNewConstMetric(o.prom.counterDomainsSf, prometheus.CounterValue,
		float64(len(o.sfdomains)),
	)
	// Requesters counter
	ch <- prometheus.MustNewConstMetric(o.prom.counterRequesters, prometheus.CounterValue,
		float64(len(o.requesters)),
	)

	// Count number of unique TLDs
	ch <- prometheus.MustNewConstMetric(o.prom.counterTlds, prometheus.CounterValue,
		float64(len(o.tlds)),
	)

	// Count number of unique suspicious names
	ch <- prometheus.MustNewConstMetric(o.prom.counterSuspicious, prometheus.CounterValue,
		float64(len(o.suspicious)),
	)

	// Count number of unique unanswered (timedout) names
	ch <- prometheus.MustNewConstMetric(o.prom.counterEvicted, prometheus.CounterValue,
		float64(len(o.evicted)),
	)
	for _, r := range o.topDomains.Get() {
		ch <- prometheus.MustNewConstMetric(o.prom.gaugeTopDomains, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range o.topNxDomains.Get() {
		ch <- prometheus.MustNewConstMetric(o.prom.gaugeTopNxDomains, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range o.topSfDomains.Get() {
		ch <- prometheus.MustNewConstMetric(o.prom.gaugeTopSfDomains, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range o.topRequesters.Get() {
		ch <- prometheus.MustNewConstMetric(o.prom.gaugeTopRequesters, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range o.topTlds.Get() {
		ch <- prometheus.MustNewConstMetric(o.prom.gaugeTopTlds, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range o.topSuspicious.Get() {
		ch <- prometheus.MustNewConstMetric(o.prom.gaugeTopSuspicious, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range o.topEvicted.Get() {
		ch <- prometheus.MustNewConstMetric(o.prom.gaugeTopEvicted, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	ch <- prometheus.MustNewConstMetric(o.prom.gaugeEps, prometheus.GaugeValue,
		float64(o.epsCounters.Eps),
	)
	ch <- prometheus.MustNewConstMetric(o.prom.gaugeEpsMax, prometheus.GaugeValue,
		float64(o.epsCounters.EpsMax),
	)

	//Update qtypes counter
	for k, v := range o.epsCounters.TotalQtypes {
		ch <- prometheus.MustNewConstMetric(o.prom.counterQtypes, prometheus.CounterValue,
			v, k,
		)
	}

	// Update Return Codes counter
	for k, v := range o.epsCounters.TotalRcodes {
		ch <- prometheus.MustNewConstMetric(o.prom.counterRcodes, prometheus.CounterValue,
			v, k,
		)
	}

	// Update IP protocol counter
	for k, v := range o.epsCounters.TotalIPProtocol {
		ch <- prometheus.MustNewConstMetric(o.prom.counterIPProtocol, prometheus.CounterValue,
			v, k,
		)
	}

	// Update IP version counter
	for k, v := range o.epsCounters.TotalIPVersion {
		ch <- prometheus.MustNewConstMetric(o.prom.counterIPVersion, prometheus.CounterValue,
			v, k,
		)
	}

	// Update global number of dns messages
	ch <- prometheus.MustNewConstMetric(o.prom.counterDnsMessages, prometheus.CounterValue,
		o.epsCounters.TotalDnsMessages)

	// Update number of dns queries
	ch <- prometheus.MustNewConstMetric(o.prom.counterDnsQueries, prometheus.CounterValue,
		float64(o.epsCounters.TotalQueries))

	// Update number of dns replies
	ch <- prometheus.MustNewConstMetric(o.prom.counterDnsReplies, prometheus.CounterValue,
		float64(o.epsCounters.TotalReplies))

	// Update flags
	ch <- prometheus.MustNewConstMetric(o.prom.counterFlagsTC, prometheus.CounterValue,
		o.epsCounters.TotalTC)
	ch <- prometheus.MustNewConstMetric(o.prom.counterFlagsAA, prometheus.CounterValue,
		o.epsCounters.TotalAA)
	ch <- prometheus.MustNewConstMetric(o.prom.counterFlagsRA, prometheus.CounterValue,
		o.epsCounters.TotalRA)
	ch <- prometheus.MustNewConstMetric(o.prom.counterFlagsAD, prometheus.CounterValue,
		o.epsCounters.TotalAD)
	ch <- prometheus.MustNewConstMetric(o.prom.counterFlagsMalformed, prometheus.CounterValue,
		o.epsCounters.TotalMalformed)
	ch <- prometheus.MustNewConstMetric(o.prom.counterFlagsFragmented, prometheus.CounterValue,
		o.epsCounters.TotalFragmented)
	ch <- prometheus.MustNewConstMetric(o.prom.counterFlagsReassembled, prometheus.CounterValue,
		o.epsCounters.TotalReasembled)

	ch <- prometheus.MustNewConstMetric(o.prom.totalBytes,
		prometheus.CounterValue, float64(o.epsCounters.TotalBytes),
	)
	ch <- prometheus.MustNewConstMetric(o.prom.totalReceivedBytes, prometheus.CounterValue,
		float64(o.epsCounters.TotalBytesReceived),
	)
	ch <- prometheus.MustNewConstMetric(o.prom.totalSentBytes, prometheus.CounterValue,
		float64(o.epsCounters.TotalBytesSent))

}

func (o *PrometheusCountersSet) ComputeEventsPerSecond() {
	o.Lock()
	defer o.Unlock()
	if o.epsCounters.TotalEvents > 0 && o.epsCounters.TotalEventsPrev > 0 {
		o.epsCounters.Eps = o.epsCounters.TotalEvents - o.epsCounters.TotalEventsPrev
	}
	o.epsCounters.TotalEventsPrev = o.epsCounters.TotalEvents
	if o.epsCounters.Eps > o.epsCounters.EpsMax {
		o.epsCounters.EpsMax = o.epsCounters.Eps
	}
}

func NewPromCounterCatalogueContainer(p *Prometheus, sel_labels []string, l map[string]string) *PromCounterCatalogueContainer {
	if len(sel_labels) == 0 {
		panic("Cannot create a new PromCounterCatalogueContainer with empty list of sel_labels")
	}
	sel, ok := catalogueSelectors[sel_labels[0]]
	if !ok {
		panic(fmt.Sprintf("No selector for %v label", sel_labels[0]))
	}

	// copy all the data over, to make sure this container does not share memory with other containers
	r := &PromCounterCatalogueContainer{
		prom:        p,
		stats:       make(map[string]PrometheusCountersCatalogue),
		selector:    sel,
		label_names: make([]string, len(sel_labels)),
		labels:      make(map[string]string),
	}
	for k, v := range l {
		r.labels[k] = v
	}
	copy(r.label_names, sel_labels)
	return r
}

// Returns a slice of all PrometheusCountersSet in a Container
func (c *PromCounterCatalogueContainer) GetAllCounterSets() []*PrometheusCountersSet {
	ret := []*PrometheusCountersSet{}
	c.RLock()
	for _, v := range c.stats {
		switch elem := v.(type) {
		case *PrometheusCountersSet:
			ret = append(ret, elem)
		case *PromCounterCatalogueContainer:
			ret = append(ret, elem.GetAllCounterSets()...)
		default:
			panic(fmt.Sprintf("Unexpected element in PromCounterCatalogueContainer of %T: %v", v, v))
		}
	}
	c.RUnlock()
	return ret
}

// Searches for an existing element for a label value, creating one if not found
func (c *PromCounterCatalogueContainer) GetCountersSet(dm *dnsutils.DnsMessage) PrometheusCountersCatalogue {
	if c.selector == nil {
		panic(fmt.Sprintf("%v: nil selector", c))
	}

	// c.selector fetches the value for the label *this* Catalogue Element considers.
	// Check if we alreday have item for it, and return it if we do (it is either catalogue or counter set)
	lbl := c.selector(dm)
	c.Lock()
	defer c.Unlock()
	if r, ok := c.stats[lbl]; ok {
		return r.GetCountersSet(dm)
	}

	// there is no existing element in the catalogue. We need to create a new entry.
	// Entry may be a new Catalogue, or PrometheusCounterSet.
	// If selector_labels consists of single element, we need to create a PrometheusCounterSet.
	// Otherwise, there is another layer of labels.
	var newElem PrometheusCountersCatalogue
	// Prepare labels for the new element (needed for ether CatalogueContainer and CounterSet)
	newLables := map[string]string{
		c.label_names[0]: lbl,
	}
	for k, v := range c.labels {
		newLables[k] = v
	}
	if len(c.label_names) > 1 {
		newElem = NewPromCounterCatalogueContainer(
			c.prom,
			c.label_names[1:],
			newLables, // Here we'll do an extra map copy...
		)
	} else {
		newElem = newPrometheusCounterSet(
			c.prom,
			prometheus.Labels(newLables),
		)

	}
	c.stats[lbl] = newElem

	// GetCountersSet of the newly created element may take some time, and we will be holding the lock
	// of the current Container until it is done. This may be improved if we separate c.stats[lbl]
	// update and calling GetCountersSet on the new element.
	return c.stats[lbl].GetCountersSet(dm)
}

// This function checks the configuration, to determine which label dimentions were requested
// by configuration, and returns correct implementation of Catalogue.
func CreateSystemCatalogue(prom *Prometheus) ([]string, *PromCounterCatalogueContainer) {
	lbls := prom.config.Loggers.Prometheus.LabelsList

	// Default configuration is label with stream_id, to keep us backward compatible
	if len(lbls) == 0 {
		lbls = []string{"stream_id"}
	}
	return lbls, NewPromCounterCatalogueContainer(
		prom,
		lbls,
		make(map[string]string),
	)
}

func NewPrometheus(config *dnsutils.Config, logger *logger.Logger, name string) *Prometheus {
	logger.Info("[%s] logger=prometheus - enabled", name)
	o := &Prometheus{
		doneApi:      make(chan bool),
		stopProcess:  make(chan bool),
		doneProcess:  make(chan bool),
		stopRun:      make(chan bool),
		doneRun:      make(chan bool),
		config:       config,
		configChan:   make(chan *dnsutils.Config),
		inputChan:    make(chan dnsutils.DnsMessage, config.Loggers.Prometheus.ChannelBufferSize),
		outputChan:   make(chan dnsutils.DnsMessage, config.Loggers.Prometheus.ChannelBufferSize),
		logger:       logger,
		promRegistry: prometheus.NewPedanticRegistry(),
		name:         name,
	}

	// This will create a catalogue of counters indexed by fileds requested by config
	o.catalogueLabels, o.counters = CreateSystemCatalogue(o)

	// init prometheus
	o.InitProm()

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

	// register metric about current version information.
	o.promRegistry.MustRegister(version.NewCollector(prom_prefix))

	// export Go runtime metrics
	o.promRegistry.MustRegister(
		collectors.NewGoCollector(collectors.WithGoCollectorMemStatsMetricsDisabled()),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	// also try collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),

	// Metric description created in Prometheus object, but used in Describe method of PrometheusCounterSet
	// Prometheus class itself reports signle metric - BuildInfo.
	o.gaugeTopDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_domains", prom_prefix),
		"Number of hit per domain topN, partitioned by qname",
		[]string{"domain"}, nil,
	)
	o.gaugeTopNxDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_nxdomains", prom_prefix),
		"Number of hit per nx domain topN, partitioned by qname",
		[]string{"domain"}, nil,
	)

	o.gaugeTopSfDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_sfdomains", prom_prefix),
		"Number of hit per servfail domain topN, partitioned by stream and qname",
		[]string{"domain"}, nil,
	)

	o.gaugeTopRequesters = prometheus.NewDesc(
		fmt.Sprintf("%s_top_requesters", prom_prefix),
		"Number of hit per requester topN, partitioned by client IP",
		[]string{"ip"}, nil,
	)

	o.gaugeTopTlds = prometheus.NewDesc(
		fmt.Sprintf("%s_top_tlds", prom_prefix),
		"Number of hit per tld - topN",
		[]string{"suffix"}, nil,
	)

	o.gaugeTopSuspicious = prometheus.NewDesc(
		fmt.Sprintf("%s_top_suspicious", prom_prefix),
		"Number of hit per suspicious domain - topN",
		[]string{"domain"}, nil,
	)

	o.gaugeTopEvicted = prometheus.NewDesc(
		fmt.Sprintf("%s_top_unanswered", prom_prefix),
		"Number of hit per unanswered domain - topN",
		[]string{"domain"}, nil,
	)

	o.gaugeEps = prometheus.NewDesc(
		fmt.Sprintf("%s_throughput_ops", prom_prefix),
		"Number of ops per second received, partitioned by stream",
		nil, nil,
	)

	o.gaugeEpsMax = prometheus.NewDesc(
		fmt.Sprintf("%s_throughput_ops_max", prom_prefix),
		"Max number of ops per second observed, partitioned by stream",
		nil, nil,
	)

	// Counter metrics
	o.counterDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_domains_total", prom_prefix),
		"The total number of domains per stream identity",
		nil, nil,
	)

	o.counterDomainsNx = prometheus.NewDesc(
		fmt.Sprintf("%s_nxdomains_total", prom_prefix),
		"The total number of unknown domains per stream identity",
		nil, nil,
	)

	o.counterDomainsSf = prometheus.NewDesc(
		fmt.Sprintf("%s_sfdomains_total", prom_prefix),
		"The total number of serverfail domains per stream identity",
		nil, nil,
	)

	o.counterRequesters = prometheus.NewDesc(
		fmt.Sprintf("%s_requesters_total", prom_prefix),
		"The total number of DNS clients per stream identity",
		nil, nil,
	)

	o.counterTlds = prometheus.NewDesc(
		fmt.Sprintf("%s_tlds_total", prom_prefix),
		"The total number of tld per stream identity",
		nil, nil,
	)

	o.counterSuspicious = prometheus.NewDesc(
		fmt.Sprintf("%s_suspicious_total", prom_prefix),
		"The total number of suspicious domain per stream identity",
		nil, nil,
	)

	o.counterEvicted = prometheus.NewDesc(
		fmt.Sprintf("%s_unanswered_total", prom_prefix),
		"The total number of unanswered domains per stream identity",
		nil, nil,
	)

	o.counterQtypes = prometheus.NewDesc(
		fmt.Sprintf("%s_qtypes_total", prom_prefix),
		"Counter of queries per qtypes",
		[]string{"query_type"}, nil,
	)

	o.counterRcodes = prometheus.NewDesc(
		fmt.Sprintf("%s_rcodes_total", prom_prefix),
		"Counter of replies per return codes",
		[]string{"return_code"}, nil,
	)

	o.counterIPProtocol = prometheus.NewDesc(
		fmt.Sprintf("%s_ipprotocol_total", prom_prefix),
		"Counter of packets per IP protocol",
		[]string{"net_transport"}, nil,
	)

	o.counterIPVersion = prometheus.NewDesc(
		fmt.Sprintf("%s_ipversion_total", prom_prefix),
		"Counter of packets per IP version",
		[]string{"net_family"}, nil,
	)

	o.counterDnsMessages = prometheus.NewDesc(
		fmt.Sprintf("%s_dnsmessages_total", prom_prefix),
		"Counter of DNS messages per stream",
		nil, nil,
	)

	o.counterDnsQueries = prometheus.NewDesc(
		fmt.Sprintf("%s_queries_total", prom_prefix),
		"Counter of DNS queries per stream",
		nil, nil,
	)

	o.counterDnsReplies = prometheus.NewDesc(
		fmt.Sprintf("%s_replies_total", prom_prefix),
		"Counter of DNS replies per stream",
		nil, nil,
	)

	o.counterFlagsTC = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_tc_total", prom_prefix),
		"Number of packet with flag TC",
		nil, nil,
	)

	o.counterFlagsAA = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_aa_total", prom_prefix),
		"Number of packet with flag AA",
		nil, nil,
	)

	o.counterFlagsRA = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_ra_total", prom_prefix),
		"Number of packet with flag RA",
		nil, nil,
	)

	o.counterFlagsAD = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_ad_total", prom_prefix),
		"Number of packet with flag AD",
		nil, nil,
	)

	o.counterFlagsMalformed = prometheus.NewDesc(
		fmt.Sprintf("%s_malformed_total", prom_prefix),
		"Number of malformed packets",
		nil, nil,
	)

	o.counterFlagsFragmented = prometheus.NewDesc(
		fmt.Sprintf("%s_fragmented_total", prom_prefix),
		"Number of IP fragmented packets",
		nil, nil,
	)

	o.counterFlagsReassembled = prometheus.NewDesc(
		fmt.Sprintf("%s_reassembled_total", prom_prefix),
		"Number of TCP reassembled packets",
		nil, nil,
	)

	o.totalBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_bytes_total", prom_prefix),
		"The total bytes received and sent",
		nil, nil,
	)

	o.totalReceivedBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_received_bytes_total", prom_prefix),
		"The total bytes received",
		nil, nil,
	)

	o.totalSentBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_sent_bytes_total", prom_prefix),
		"The total bytes sent",
		nil, nil,
	)

	o.histogramQueriesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_queries_size_bytes", prom_prefix),
			Help:    "Size of the queries in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		o.catalogueLabels,
	)
	o.promRegistry.MustRegister(o.histogramQueriesLength)

	o.histogramRepliesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_replies_size_bytes", prom_prefix),
			Help:    "Size of the replies in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		o.catalogueLabels,
	)
	o.promRegistry.MustRegister(o.histogramRepliesLength)

	o.histogramQnamesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_qnames_size_bytes", prom_prefix),
			Help:    "Size of the qname in bytes.",
			Buckets: []float64{10, 20, 40, 60, 100},
		},
		o.catalogueLabels,
	)
	o.promRegistry.MustRegister(o.histogramQnamesLength)

	o.histogramLatencies = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_latencies", prom_prefix),
			Help:    "Latency between query and reply",
			Buckets: []float64{0.001, 0.010, 0.050, 0.100, 0.5, 1.0},
		},
		o.catalogueLabels,
	)
	o.promRegistry.MustRegister(o.histogramLatencies)
}

func (o *Prometheus) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.Prometheus.TlsMinVersion) {
		o.logger.Fatal("logger prometheus - invalid tls min version")
	}
}

func (o *Prometheus) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload configuration!")
	o.configChan <- config
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

	// count number of dns messages per network family (ipv4 or v6)
	v := o.counters.GetCountersSet(&dm)
	counterSet, ok := v.(*PrometheusCountersSet)
	o.Unlock()
	if !ok {
		o.LogError(fmt.Sprintf("Prometheus logger - GetCountersSet returned an invalid value of %T, expected *PrometheusCountersSet", v))
	} else {
		counterSet.Record(dm)
	}

}

func (o *Prometheus) ComputeEventsPerSecond() {
	// for each stream compute the number of events per second
	o.Lock()
	defer o.Unlock()
	for _, cntrSet := range o.counters.GetAllCounterSets() {
		cntrSet.ComputeEventsPerSecond()
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

		case cfg, opened := <-s.configChan:
			if !opened {
				return
			}
			s.config = cfg
			s.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

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

/*
This is an implementation of variadic dimentions map of label values.
Having nested structure offers the fastest operations, compared to super-flexibile approach that prom client
uses with arbitrary set of labels.

Label values are obtained by the means of 'selectors' - functions that fetch a specific field of a DNS Message
offering fast operations.

Example of conterSet/Container for 2 labels

+----------------------------------------------------------------------------------------------------------+
| Container for label1                                                                                     |
| Container maps different values of label1 to other containers                                            |
| until the chain for all required label names is built.                                                   |
|                                                                                                          |
| Label1 values:                                                                                           |
|         value11                                                                 value12                  |
| +---------------------------------------------------------------------------+ +-------------------------+|
| | Container for label2                                                      | | Container for label2    ||
| | in this container ALL elements                                            | | all elemenens share     ||
| | have the same value for label1                                            | | the same value of label1||
| |                                                                           | |                         ||
| | Label2 values:                                                            | | +----------++----------+||
| |     value21                             value22                           | | | ....     ||  ,,,,,,  |||
| | +-----------------------------------++-----------------------------------+| | |          ||          |||
| | | CounterSet                        || CounterSet                        || | |          ||          |||
| | | In this set all metrics share the || In this set all metrics share the || | +----------++----------+||
| | | same values for both labels, so   || same values for both labels, so   || |                         ||
| | | no need to keep label values here || no need to keep label values here || |                         ||
| | |                                   ||                                   || |                         ||
| | | metric1                           || metric1                           || |                         ||
| | | metric2                           || metric2                           || |                         ||
| | +-----------------------------------++-----------------------------------+| |                         ||
| +---------------------------------------------------------------------------+ +-------------------------+|

*/
