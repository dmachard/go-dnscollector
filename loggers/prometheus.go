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
var catalogueSelectors map[string]func(*dnsutils.DNSMessage) string = map[string]func(*dnsutils.DNSMessage) string{
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
	TotalDNSMessages   float64
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
	GetCountersSet(*dnsutils.DNSMessage) PrometheusCountersCatalogue
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

	// labelNames - is a list of label *names* for PromCounterCatalogueContainer's in stats
	// map to use to get proper selectors.
	// The topmost instance of PromCounterCatalogueContainer has the full list of all names to
	// consider (the one provided by the config). Whenver it needs to create a new item in
	// it's stats map, it suplies labelNames[1:] to the constructor for the lower level
	// container to get the selector for the next level
	labelNames []string // This is list of label names for nested containers

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
	selector func(*dnsutils.DNSMessage) string

	sync.RWMutex
}

/*
Selectors
*/
func GetStreamID(dm *dnsutils.DNSMessage) string {
	return dm.DNSTap.Identity
}

func GetResolverIP(dm *dnsutils.DNSMessage) string {
	return dm.NetworkInfo.ResponseIP
}

type Prometheus struct {
	doneAPI      chan bool
	stopProcess  chan bool
	doneProcess  chan bool
	stopRun      chan bool
	doneRun      chan bool
	httpServer   *http.Server
	netListener  net.Listener
	inputChan    chan dnsutils.DNSMessage
	outputChan   chan dnsutils.DNSMessage
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
	counterDNSMessages *prometheus.Desc
	counterDNSQueries  *prometheus.Desc
	counterDNSReplies  *prometheus.Desc

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

func (c *PrometheusCountersSet) GetCountersSet(dm *dnsutils.DNSMessage) PrometheusCountersCatalogue {
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
	ch <- c.prom.counterDNSMessages
	ch <- c.prom.counterDNSQueries
	ch <- c.prom.counterDNSReplies

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
func (c *PrometheusCountersSet) Record(dm dnsutils.DNSMessage) {
	c.Lock()
	defer c.Unlock()
	// count number of dns message per requester ip and top clients
	if _, exists := c.requesters[dm.NetworkInfo.QueryIP]; !exists {
		c.requesters[dm.NetworkInfo.QueryIP] = 1
	} else {
		c.requesters[dm.NetworkInfo.QueryIP] += 1
	}
	c.topRequesters.Record(dm.NetworkInfo.QueryIP, c.requesters[dm.NetworkInfo.QueryIP])

	// top domains
	switch dm.DNS.Rcode {
	case dnsutils.DNSRcodeTimeout:
		if _, exists := c.evicted[dm.DNS.Qname]; !exists {
			c.evicted[dm.DNS.Qname] = 1
		} else {
			c.evicted[dm.DNS.Qname] += 1
		}
		c.topEvicted.Record(dm.DNS.Qname, c.evicted[dm.DNS.Qname])

	case dnsutils.DNSRcodeServFail:
		if _, exists := c.sfdomains[dm.DNS.Qname]; !exists {
			c.sfdomains[dm.DNS.Qname] = 1
		} else {
			c.sfdomains[dm.DNS.Qname] += 1
		}

		c.topSfDomains.Record(dm.DNS.Qname, c.sfdomains[dm.DNS.Qname])

	case dnsutils.DNSRcodeNXDomain:
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

		if dm.DNSTap.Latency > 0.0 {
			c.prom.histogramLatencies.With(c.labels).Observe(dm.DNSTap.Latency)
		}

		if dm.DNS.Type == dnsutils.DNSQuery {
			c.prom.histogramQueriesLength.With(c.labels).Observe(float64(dm.DNS.Length))
		} else {
			c.prom.histogramRepliesLength.With(c.labels).Observe(float64(dm.DNS.Length))
		}
	}

	// Record EPS related data
	c.epsCounters.TotalEvents++
	c.epsCounters.TotalBytes += dm.DNS.Length
	c.epsCounters.TotalDNSMessages++

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

	if dm.DNS.Type == dnsutils.DNSQuery {
		c.epsCounters.TotalBytesReceived += dm.DNS.Length
		c.epsCounters.TotalQueries++
	}
	if dm.DNS.Type == dnsutils.DNSReply {
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
	if dm.NetworkInfo.IPDefragmented {
		c.epsCounters.TotalFragmented++
	}
	if dm.NetworkInfo.TCPReassembled {
		c.epsCounters.TotalReasembled++
	}

}

func (c *PrometheusCountersSet) Collect(ch chan<- prometheus.Metric) {
	c.Lock()
	defer c.Unlock()
	// Update number of domains
	ch <- prometheus.MustNewConstMetric(c.prom.counterDomains, prometheus.CounterValue,
		float64(len(c.domains)),
	)
	// Count NX domains
	ch <- prometheus.MustNewConstMetric(c.prom.counterDomainsNx, prometheus.CounterValue,
		float64(len(c.nxdomains)),
	)
	// Count SERVFAIL domains
	ch <- prometheus.MustNewConstMetric(c.prom.counterDomainsSf, prometheus.CounterValue,
		float64(len(c.sfdomains)),
	)
	// Requesters counter
	ch <- prometheus.MustNewConstMetric(c.prom.counterRequesters, prometheus.CounterValue,
		float64(len(c.requesters)),
	)

	// Count number of unique TLDs
	ch <- prometheus.MustNewConstMetric(c.prom.counterTlds, prometheus.CounterValue,
		float64(len(c.tlds)),
	)

	// Count number of unique suspicious names
	ch <- prometheus.MustNewConstMetric(c.prom.counterSuspicious, prometheus.CounterValue,
		float64(len(c.suspicious)),
	)

	// Count number of unique unanswered (timedout) names
	ch <- prometheus.MustNewConstMetric(c.prom.counterEvicted, prometheus.CounterValue,
		float64(len(c.evicted)),
	)
	for _, r := range c.topDomains.Get() {
		ch <- prometheus.MustNewConstMetric(c.prom.gaugeTopDomains, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range c.topNxDomains.Get() {
		ch <- prometheus.MustNewConstMetric(c.prom.gaugeTopNxDomains, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range c.topSfDomains.Get() {
		ch <- prometheus.MustNewConstMetric(c.prom.gaugeTopSfDomains, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range c.topRequesters.Get() {
		ch <- prometheus.MustNewConstMetric(c.prom.gaugeTopRequesters, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range c.topTlds.Get() {
		ch <- prometheus.MustNewConstMetric(c.prom.gaugeTopTlds, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range c.topSuspicious.Get() {
		ch <- prometheus.MustNewConstMetric(c.prom.gaugeTopSuspicious, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	for _, r := range c.topEvicted.Get() {
		ch <- prometheus.MustNewConstMetric(c.prom.gaugeTopEvicted, prometheus.GaugeValue,
			float64(r.Hit), r.Name)
	}

	ch <- prometheus.MustNewConstMetric(c.prom.gaugeEps, prometheus.GaugeValue,
		float64(c.epsCounters.Eps),
	)
	ch <- prometheus.MustNewConstMetric(c.prom.gaugeEpsMax, prometheus.GaugeValue,
		float64(c.epsCounters.EpsMax),
	)

	//Update qtypes counter
	for k, v := range c.epsCounters.TotalQtypes {
		ch <- prometheus.MustNewConstMetric(c.prom.counterQtypes, prometheus.CounterValue,
			v, k,
		)
	}

	// Update Return Codes counter
	for k, v := range c.epsCounters.TotalRcodes {
		ch <- prometheus.MustNewConstMetric(c.prom.counterRcodes, prometheus.CounterValue,
			v, k,
		)
	}

	// Update IP protocol counter
	for k, v := range c.epsCounters.TotalIPProtocol {
		ch <- prometheus.MustNewConstMetric(c.prom.counterIPProtocol, prometheus.CounterValue,
			v, k,
		)
	}

	// Update IP version counter
	for k, v := range c.epsCounters.TotalIPVersion {
		ch <- prometheus.MustNewConstMetric(c.prom.counterIPVersion, prometheus.CounterValue,
			v, k,
		)
	}

	// Update global number of dns messages
	ch <- prometheus.MustNewConstMetric(c.prom.counterDNSMessages, prometheus.CounterValue,
		c.epsCounters.TotalDNSMessages)

	// Update number of dns queries
	ch <- prometheus.MustNewConstMetric(c.prom.counterDNSQueries, prometheus.CounterValue,
		float64(c.epsCounters.TotalQueries))

	// Update number of dns replies
	ch <- prometheus.MustNewConstMetric(c.prom.counterDNSReplies, prometheus.CounterValue,
		float64(c.epsCounters.TotalReplies))

	// Update flags
	ch <- prometheus.MustNewConstMetric(c.prom.counterFlagsTC, prometheus.CounterValue,
		c.epsCounters.TotalTC)
	ch <- prometheus.MustNewConstMetric(c.prom.counterFlagsAA, prometheus.CounterValue,
		c.epsCounters.TotalAA)
	ch <- prometheus.MustNewConstMetric(c.prom.counterFlagsRA, prometheus.CounterValue,
		c.epsCounters.TotalRA)
	ch <- prometheus.MustNewConstMetric(c.prom.counterFlagsAD, prometheus.CounterValue,
		c.epsCounters.TotalAD)
	ch <- prometheus.MustNewConstMetric(c.prom.counterFlagsMalformed, prometheus.CounterValue,
		c.epsCounters.TotalMalformed)
	ch <- prometheus.MustNewConstMetric(c.prom.counterFlagsFragmented, prometheus.CounterValue,
		c.epsCounters.TotalFragmented)
	ch <- prometheus.MustNewConstMetric(c.prom.counterFlagsReassembled, prometheus.CounterValue,
		c.epsCounters.TotalReasembled)

	ch <- prometheus.MustNewConstMetric(c.prom.totalBytes,
		prometheus.CounterValue, float64(c.epsCounters.TotalBytes),
	)
	ch <- prometheus.MustNewConstMetric(c.prom.totalReceivedBytes, prometheus.CounterValue,
		float64(c.epsCounters.TotalBytesReceived),
	)
	ch <- prometheus.MustNewConstMetric(c.prom.totalSentBytes, prometheus.CounterValue,
		float64(c.epsCounters.TotalBytesSent))

}

func (c *PrometheusCountersSet) ComputeEventsPerSecond() {
	c.Lock()
	defer c.Unlock()
	if c.epsCounters.TotalEvents > 0 && c.epsCounters.TotalEventsPrev > 0 {
		c.epsCounters.Eps = c.epsCounters.TotalEvents - c.epsCounters.TotalEventsPrev
	}
	c.epsCounters.TotalEventsPrev = c.epsCounters.TotalEvents
	if c.epsCounters.Eps > c.epsCounters.EpsMax {
		c.epsCounters.EpsMax = c.epsCounters.Eps
	}
}

func NewPromCounterCatalogueContainer(p *Prometheus, selLabels []string, l map[string]string) *PromCounterCatalogueContainer {
	if len(selLabels) == 0 {
		panic("Cannot create a new PromCounterCatalogueContainer with empty list of sel_labels")
	}
	sel, ok := catalogueSelectors[selLabels[0]]
	if !ok {
		panic(fmt.Sprintf("No selector for %v label", selLabels[0]))
	}

	// copy all the data over, to make sure this container does not share memory with other containers
	r := &PromCounterCatalogueContainer{
		prom:       p,
		stats:      make(map[string]PrometheusCountersCatalogue),
		selector:   sel,
		labelNames: make([]string, len(selLabels)),
		labels:     make(map[string]string),
	}
	for k, v := range l {
		r.labels[k] = v
	}
	copy(r.labelNames, selLabels)
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
func (c *PromCounterCatalogueContainer) GetCountersSet(dm *dnsutils.DNSMessage) PrometheusCountersCatalogue {
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
		c.labelNames[0]: lbl,
	}
	for k, v := range c.labels {
		newLables[k] = v
	}
	if len(c.labelNames) > 1 {
		newElem = NewPromCounterCatalogueContainer(
			c.prom,
			c.labelNames[1:],
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
		doneAPI:      make(chan bool),
		stopProcess:  make(chan bool),
		doneProcess:  make(chan bool),
		stopRun:      make(chan bool),
		doneRun:      make(chan bool),
		config:       config,
		configChan:   make(chan *dnsutils.Config),
		inputChan:    make(chan dnsutils.DNSMessage, config.Loggers.Prometheus.ChannelBufferSize),
		outputChan:   make(chan dnsutils.DNSMessage, config.Loggers.Prometheus.ChannelBufferSize),
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

func (c *Prometheus) InitProm() {

	promPrefix := SanitizeMetricName(c.config.Loggers.Prometheus.PromPrefix)

	// register metric about current version information.
	c.promRegistry.MustRegister(version.NewCollector(promPrefix))

	// export Go runtime metrics
	c.promRegistry.MustRegister(
		collectors.NewGoCollector(collectors.WithGoCollectorMemStatsMetricsDisabled()),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	// also try collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),

	// Metric description created in Prometheus object, but used in Describe method of PrometheusCounterSet
	// Prometheus class itself reports signle metric - BuildInfo.
	c.gaugeTopDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_domains", promPrefix),
		"Number of hit per domain topN, partitioned by qname",
		[]string{"domain"}, nil,
	)
	c.gaugeTopNxDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_nxdomains", promPrefix),
		"Number of hit per nx domain topN, partitioned by qname",
		[]string{"domain"}, nil,
	)

	c.gaugeTopSfDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_sfdomains", promPrefix),
		"Number of hit per servfail domain topN, partitioned by stream and qname",
		[]string{"domain"}, nil,
	)

	c.gaugeTopRequesters = prometheus.NewDesc(
		fmt.Sprintf("%s_top_requesters", promPrefix),
		"Number of hit per requester topN, partitioned by client IP",
		[]string{"ip"}, nil,
	)

	c.gaugeTopTlds = prometheus.NewDesc(
		fmt.Sprintf("%s_top_tlds", promPrefix),
		"Number of hit per tld - topN",
		[]string{"suffix"}, nil,
	)

	c.gaugeTopSuspicious = prometheus.NewDesc(
		fmt.Sprintf("%s_top_suspicious", promPrefix),
		"Number of hit per suspicious domain - topN",
		[]string{"domain"}, nil,
	)

	c.gaugeTopEvicted = prometheus.NewDesc(
		fmt.Sprintf("%s_top_unanswered", promPrefix),
		"Number of hit per unanswered domain - topN",
		[]string{"domain"}, nil,
	)

	c.gaugeEps = prometheus.NewDesc(
		fmt.Sprintf("%s_throughput_ops", promPrefix),
		"Number of ops per second received, partitioned by stream",
		nil, nil,
	)

	c.gaugeEpsMax = prometheus.NewDesc(
		fmt.Sprintf("%s_throughput_ops_max", promPrefix),
		"Max number of ops per second observed, partitioned by stream",
		nil, nil,
	)

	// Counter metrics
	c.counterDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_domains_total", promPrefix),
		"The total number of domains per stream identity",
		nil, nil,
	)

	c.counterDomainsNx = prometheus.NewDesc(
		fmt.Sprintf("%s_nxdomains_total", promPrefix),
		"The total number of unknown domains per stream identity",
		nil, nil,
	)

	c.counterDomainsSf = prometheus.NewDesc(
		fmt.Sprintf("%s_sfdomains_total", promPrefix),
		"The total number of serverfail domains per stream identity",
		nil, nil,
	)

	c.counterRequesters = prometheus.NewDesc(
		fmt.Sprintf("%s_requesters_total", promPrefix),
		"The total number of DNS clients per stream identity",
		nil, nil,
	)

	c.counterTlds = prometheus.NewDesc(
		fmt.Sprintf("%s_tlds_total", promPrefix),
		"The total number of tld per stream identity",
		nil, nil,
	)

	c.counterSuspicious = prometheus.NewDesc(
		fmt.Sprintf("%s_suspicious_total", promPrefix),
		"The total number of suspicious domain per stream identity",
		nil, nil,
	)

	c.counterEvicted = prometheus.NewDesc(
		fmt.Sprintf("%s_unanswered_total", promPrefix),
		"The total number of unanswered domains per stream identity",
		nil, nil,
	)

	c.counterQtypes = prometheus.NewDesc(
		fmt.Sprintf("%s_qtypes_total", promPrefix),
		"Counter of queries per qtypes",
		[]string{"query_type"}, nil,
	)

	c.counterRcodes = prometheus.NewDesc(
		fmt.Sprintf("%s_rcodes_total", promPrefix),
		"Counter of replies per return codes",
		[]string{"return_code"}, nil,
	)

	c.counterIPProtocol = prometheus.NewDesc(
		fmt.Sprintf("%s_ipprotocol_total", promPrefix),
		"Counter of packets per IP protocol",
		[]string{"net_transport"}, nil,
	)

	c.counterIPVersion = prometheus.NewDesc(
		fmt.Sprintf("%s_ipversion_total", promPrefix),
		"Counter of packets per IP version",
		[]string{"net_family"}, nil,
	)

	c.counterDNSMessages = prometheus.NewDesc(
		fmt.Sprintf("%s_dnsmessages_total", promPrefix),
		"Counter of DNS messages per stream",
		nil, nil,
	)

	c.counterDNSQueries = prometheus.NewDesc(
		fmt.Sprintf("%s_queries_total", promPrefix),
		"Counter of DNS queries per stream",
		nil, nil,
	)

	c.counterDNSReplies = prometheus.NewDesc(
		fmt.Sprintf("%s_replies_total", promPrefix),
		"Counter of DNS replies per stream",
		nil, nil,
	)

	c.counterFlagsTC = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_tc_total", promPrefix),
		"Number of packet with flag TC",
		nil, nil,
	)

	c.counterFlagsAA = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_aa_total", promPrefix),
		"Number of packet with flag AA",
		nil, nil,
	)

	c.counterFlagsRA = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_ra_total", promPrefix),
		"Number of packet with flag RA",
		nil, nil,
	)

	c.counterFlagsAD = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_ad_total", promPrefix),
		"Number of packet with flag AD",
		nil, nil,
	)

	c.counterFlagsMalformed = prometheus.NewDesc(
		fmt.Sprintf("%s_malformed_total", promPrefix),
		"Number of malformed packets",
		nil, nil,
	)

	c.counterFlagsFragmented = prometheus.NewDesc(
		fmt.Sprintf("%s_fragmented_total", promPrefix),
		"Number of IP fragmented packets",
		nil, nil,
	)

	c.counterFlagsReassembled = prometheus.NewDesc(
		fmt.Sprintf("%s_reassembled_total", promPrefix),
		"Number of TCP reassembled packets",
		nil, nil,
	)

	c.totalBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_bytes_total", promPrefix),
		"The total bytes received and sent",
		nil, nil,
	)

	c.totalReceivedBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_received_bytes_total", promPrefix),
		"The total bytes received",
		nil, nil,
	)

	c.totalSentBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_sent_bytes_total", promPrefix),
		"The total bytes sent",
		nil, nil,
	)

	c.histogramQueriesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_queries_size_bytes", promPrefix),
			Help:    "Size of the queries in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		c.catalogueLabels,
	)
	c.promRegistry.MustRegister(c.histogramQueriesLength)

	c.histogramRepliesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_replies_size_bytes", promPrefix),
			Help:    "Size of the replies in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		c.catalogueLabels,
	)
	c.promRegistry.MustRegister(c.histogramRepliesLength)

	c.histogramQnamesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_qnames_size_bytes", promPrefix),
			Help:    "Size of the qname in bytes.",
			Buckets: []float64{10, 20, 40, 60, 100},
		},
		c.catalogueLabels,
	)
	c.promRegistry.MustRegister(c.histogramQnamesLength)

	c.histogramLatencies = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_latencies", promPrefix),
			Help:    "Latency between query and reply",
			Buckets: []float64{0.001, 0.010, 0.050, 0.100, 0.5, 1.0},
		},
		c.catalogueLabels,
	)
	c.promRegistry.MustRegister(c.histogramLatencies)
}

func (c *Prometheus) ReadConfig() {
	if !dnsutils.IsValidTLS(c.config.Loggers.Prometheus.TLSMinVersion) {
		c.logger.Fatal("logger prometheus - invalid tls min version")
	}
}

func (c *Prometheus) ReloadConfig(config *dnsutils.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *Prometheus) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=prometheus - "+msg, v...)
}

func (c *Prometheus) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=prometheus - "+msg, v...)
}

func (c *Prometheus) Channel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *Prometheus) Stop() {
	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess

	c.LogInfo("stopping http server...")
	c.netListener.Close()
	<-c.doneAPI
}

func (c *Prometheus) Record(dm dnsutils.DNSMessage) {
	// record stream identity
	c.Lock()

	// count number of dns messages per network family (ipv4 or v6)
	v := c.counters.GetCountersSet(&dm)
	counterSet, ok := v.(*PrometheusCountersSet)
	c.Unlock()
	if !ok {
		c.LogError(fmt.Sprintf("Prometheus logger - GetCountersSet returned an invalid value of %T, expected *PrometheusCountersSet", v))
	} else {
		counterSet.Record(dm)
	}

}

func (c *Prometheus) ComputeEventsPerSecond() {
	// for each stream compute the number of events per second
	c.Lock()
	defer c.Unlock()
	for _, cntrSet := range c.counters.GetAllCounterSets() {
		cntrSet.ComputeEventsPerSecond()
	}
}

func (c *Prometheus) ListenAndServe() {
	c.LogInfo("starting http server...")

	var err error
	var listener net.Listener
	addrlisten := c.config.Loggers.Prometheus.ListenIP + ":" + strconv.Itoa(c.config.Loggers.Prometheus.ListenPort)
	// listening with tls enabled ?
	if c.config.Loggers.Prometheus.TLSSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.config.Loggers.Prometheus.CertFile, c.config.Loggers.Prometheus.KeyFile)
		if err != nil {
			c.logger.Fatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = dnsutils.TLSVersion[c.config.Loggers.Prometheus.TLSMinVersion]

		if c.config.Loggers.Prometheus.TLSMutual {

			// Create a CA certificate pool and add cert.pem to it
			var caCert []byte
			caCert, err = os.ReadFile(c.config.Loggers.Prometheus.CertFile)
			if err != nil {
				c.logger.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		listener, err = tls.Listen(dnsutils.SocketTCP, addrlisten, tlsConfig)

	} else {
		// basic listening
		listener, err = net.Listen(dnsutils.SocketTCP, addrlisten)
	}

	// something wrong ?
	if err != nil {
		c.logger.Fatal("http server listening failed:", err)
	}

	c.netListener = listener
	c.LogInfo("is listening on %s", listener.Addr())

	c.httpServer.Serve(c.netListener)

	c.LogInfo("http server terminated")
	c.doneAPI <- true
}

func (c *Prometheus) Run() {
	c.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, c.outputChan)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel, 0)

	// start http server
	go c.ListenAndServe()

	// goroutine to process transformed dns messages
	go c.Process()

	// loop to process incoming messages
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

func (c *Prometheus) Process() {
	// init timer to compute qps
	t1Interval := 1 * time.Second
	t1 := time.NewTimer(t1Interval)

	c.LogInfo("ready to process")
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
			c.Record(dm)

		case <-t1.C:
			// compute eps each second
			c.ComputeEventsPerSecond()

			// reset the timer
			t1.Reset(t1Interval)
		}
	}
	c.LogInfo("processing terminated")
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
