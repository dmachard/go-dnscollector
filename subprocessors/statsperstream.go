package subprocessors

import (
	"strings"
	"sync"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-topmap"
)

type Counters struct {
	Pps    uint64
	PpsMax uint64

	Packets          uint64
	PacketsPrev      uint64
	PacketsMalformed uint64

	Latency0_1      uint64
	Latency1_10     uint64
	Latency10_50    uint64
	Latency50_100   uint64
	Latency100_500  uint64
	Latency500_1000 uint64
	Latency1000_inf uint64
	LatencyMax      float64
	LatencyMin      float64

	QnameLength0_10    int
	QnameLength10_20   int
	QnameLength20_40   int
	QnameLength40_60   int
	QnameLength60_100  int
	QnameLength100_Inf int
	QnameLengthMax     int
	QnameLengthMin     int

	QueryLength0_50    int
	QueryLength50_100  int
	QueryLength100_250 int
	QueryLength250_500 int
	QueryLength500_Inf int
	QueryLengthMax     int
	QueryLengthMin     int

	ReplyLength0_50    int
	ReplyLength50_100  int
	ReplyLength100_250 int
	ReplyLength250_500 int
	ReplyLength500_Inf int
	ReplyLengthMax     int
	ReplyLengthMin     int

	ReceivedBytesTotal int
	SentBytesTotal     int
}

type StatsPerStream struct {
	config *dnsutils.Config

	total                Counters
	firstleveldomains    map[string]int
	firstleveldomainstop *topmap.TopMap
	qnames               map[string]int
	qnamestop            *topmap.TopMap
	qnamesNxd            map[string]int
	qnamesNxdtop         *topmap.TopMap
	qnamesSlow           map[string]int
	qnamesSlowtop        *topmap.TopMap
	qnamesSuspicious     map[string]int
	qnamesSuspicioustop  *topmap.TopMap
	clients              map[string]int
	clientstop           *topmap.TopMap
	clientsSuspicious    map[string]int
	clientsSuspicioustop *topmap.TopMap
	rrtypes              map[string]int
	rrtypestop           *topmap.TopMap
	rcodes               map[string]int
	rcodestop            *topmap.TopMap
	operations           map[string]int
	operationstop        *topmap.TopMap
	transports           map[string]int
	transportstop        *topmap.TopMap
	ipproto              map[string]int
	ipprototop           *topmap.TopMap
	commonQtypes         map[string]bool
	sync.RWMutex
}

func NewStatsPerStream(config *dnsutils.Config) *StatsPerStream {
	c := &StatsPerStream{
		config:               config,
		total:                Counters{},
		firstleveldomains:    make(map[string]int),
		firstleveldomainstop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		qnames:               make(map[string]int),
		qnamestop:            topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		qnamesNxd:            make(map[string]int),
		qnamesNxdtop:         topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		qnamesSlow:           make(map[string]int),
		qnamesSlowtop:        topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		qnamesSuspicious:     make(map[string]int),
		qnamesSuspicioustop:  topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		clients:              make(map[string]int),
		clientstop:           topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		clientsSuspicious:    make(map[string]int),
		clientsSuspicioustop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		rrtypes:              make(map[string]int),
		rrtypestop:           topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		rcodes:               make(map[string]int),
		rcodestop:            topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		operations:           make(map[string]int),
		operationstop:        topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		transports:           make(map[string]int),
		transportstop:        topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		ipproto:              make(map[string]int),
		ipprototop:           topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),
		commonQtypes:         make(map[string]bool),
	}

	c.ReadConfig()

	return c
}

func (c *StatsPerStream) ReadConfig() {
	for _, v := range c.config.Subprocessors.Statistics.CommonQtypes {
		c.commonQtypes[v] = true
	}
}

func (c *StatsPerStream) Record(dm dnsutils.DnsMessage) {
	c.Lock()
	defer c.Unlock()

	// global number of packets
	c.total.Packets++

	// malformed packet ?
	if dm.MalformedPacket {
		c.total.PacketsMalformed++

		if _, ok := c.clientsSuspicious[dm.QueryIp]; !ok {
			c.clientsSuspicious[dm.QueryIp] = 1
		} else {
			c.clientsSuspicious[dm.QueryIp]++
		}
		c.clientsSuspicioustop.Record(dm.QueryIp, c.clientsSuspicious[dm.QueryIp])

		return
	}

	// packet size repartition
	if dm.Type == "query" {
		c.total.ReceivedBytesTotal += dm.Length

		if c.total.QueryLengthMin == 0 {
			c.total.QueryLengthMin = dm.Length
		}

		// max value
		if dm.Length > c.total.QueryLengthMax {
			c.total.QueryLengthMax = dm.Length
		}
		// min value
		if dm.Length < c.total.QueryLengthMin {
			c.total.QueryLengthMin = dm.Length
		}

		switch {
		case dm.Length <= 50:
			c.total.QueryLength0_50++
		case 50 < dm.Length && dm.Length <= 100:
			c.total.QueryLength50_100++
		case 100 < dm.Length && dm.Length <= 250:
			c.total.QueryLength100_250++
		case 250 < dm.Length && dm.Length <= 500:
			c.total.QueryLength250_500++
		default:
			c.total.QueryLength500_Inf++
		}
	} else {
		c.total.SentBytesTotal += dm.Length

		if c.total.ReplyLengthMin == 0 {
			c.total.ReplyLengthMin = dm.Length
		}

		// max value
		if dm.Length > c.total.ReplyLengthMax {
			c.total.ReplyLengthMax = dm.Length
		}
		// min value
		if dm.Length < c.total.ReplyLengthMin {
			c.total.ReplyLengthMin = dm.Length
		}

		switch {
		case dm.Length <= 50:
			c.total.ReplyLength0_50++
		case 50 < dm.Length && dm.Length <= 100:
			c.total.ReplyLength50_100++
		case 100 < dm.Length && dm.Length <= 250:
			c.total.ReplyLength100_250++
		case 250 < dm.Length && dm.Length <= 500:
			c.total.ReplyLength250_500++
		default:
			c.total.ReplyLength500_Inf++
		}
	}

	// qname length
	qnameLen := len(dm.Qname)
	if c.total.QnameLengthMin == 0 {
		c.total.QnameLengthMin = qnameLen
	}
	// max value
	if qnameLen > c.total.QnameLengthMax {
		c.total.QnameLengthMax = qnameLen
	}
	// min value
	if qnameLen < c.total.QnameLengthMin {
		c.total.QnameLengthMin = qnameLen
	}

	// qname size repartition
	switch {
	case qnameLen <= 10:
		c.total.QnameLength0_10++
	case 10 < qnameLen && qnameLen <= 20:
		c.total.QnameLength10_20++
	case 20 < qnameLen && qnameLen <= 40:
		c.total.QnameLength20_40++
	case 40 < qnameLen && qnameLen <= 60:
		c.total.QnameLength40_60++
	case 60 < qnameLen && qnameLen <= 100:
		c.total.QnameLength60_100++
	default:
		c.total.QnameLength100_Inf++
	}

	// search some suspicious domains regarding the length and
	// the qtype requested
	if qnameLen >= c.config.Subprocessors.Statistics.ThresholdQnameLen {
		if _, ok := c.qnamesSuspicious[dm.Qname]; !ok {
			c.qnamesSuspicious[dm.Qname] = 1
		} else {
			c.qnamesSuspicious[dm.Qname]++
		}
		c.qnamesSuspicioustop.Record(dm.Qname, c.qnamesSuspicious[dm.Qname])
	}

	if _, found := c.commonQtypes[dm.Qtype]; !found {
		if _, ok := c.qnamesSuspicious[dm.Qname]; !ok {
			c.qnamesSuspicious[dm.Qname] = 1
		} else {
			c.qnamesSuspicious[dm.Qname]++
		}
		c.qnamesSuspicioustop.Record(dm.Qname, c.qnamesSuspicious[dm.Qname])
	}

	if dm.Length >= c.config.Subprocessors.Statistics.ThresholdPacketLen {
		if _, ok := c.qnamesSuspicious[dm.Qname]; !ok {
			c.qnamesSuspicious[dm.Qname] = 1
		} else {
			c.qnamesSuspicious[dm.Qname]++
		}
		c.qnamesSuspicioustop.Record(dm.Qname, c.qnamesSuspicious[dm.Qname])
	}

	// latency
	if dm.Latency > c.total.LatencyMax {
		c.total.LatencyMax = dm.Latency
	}

	if dm.Latency > 0.0 {
		if c.total.LatencyMin == 0.0 {
			c.total.LatencyMin = dm.Latency
		}
		if dm.Latency < c.total.LatencyMin {
			c.total.LatencyMin = dm.Latency
		}
	}

	switch {
	case dm.Latency == 0.0:
		break
	case dm.Latency > 0.0 && dm.Latency <= 0.001:
		c.total.Latency0_1++
	case 0.001 < dm.Latency && dm.Latency <= 0.010:
		c.total.Latency1_10++
	case 0.010 < dm.Latency && dm.Latency <= 0.050:
		c.total.Latency10_50++
	case 0.050 < dm.Latency && dm.Latency <= 0.100:
		c.total.Latency50_100++
	case 0.100 < dm.Latency && dm.Latency <= 0.500:
		c.total.Latency100_500++
	case 0.500 < dm.Latency && dm.Latency <= 1.000:
		c.total.Latency500_1000++
	default:
		c.total.Latency1000_inf++
	}

	// record ip proto
	if _, ok := c.ipproto[dm.Family]; !ok {
		c.ipproto[dm.Family] = 1
	} else {
		c.ipproto[dm.Family]++
	}
	c.ipprototop.Record(dm.Family, c.ipproto[dm.Family])

	// record transports
	if _, ok := c.transports[dm.Protocol]; !ok {
		c.transports[dm.Protocol] = 1
	} else {
		c.transports[dm.Protocol]++
	}
	c.transportstop.Record(dm.Protocol, c.transports[dm.Protocol])

	// record first level domain
	i := strings.LastIndex(dm.Qname, ".")
	if i > -1 {
		fld := dm.Qname[i+1:]
		if _, ok := c.firstleveldomains[fld]; !ok {
			c.firstleveldomains[fld] = 1
		} else {
			c.firstleveldomains[fld]++
		}
		c.firstleveldomainstop.Record(fld, c.firstleveldomains[fld])
	}

	// record all qnames
	if _, ok := c.qnames[dm.Qname]; !ok {
		c.qnames[dm.Qname] = 1
	} else {
		c.qnames[dm.Qname]++
	}
	c.qnamestop.Record(dm.Qname, c.qnames[dm.Qname])

	if dm.Rcode == "NXDOMAIN" {
		if _, ok := c.qnamesNxd[dm.Qname]; !ok {
			c.qnamesNxd[dm.Qname] = 1
		} else {
			c.qnamesNxd[dm.Qname]++
		}
		c.qnamesNxdtop.Record(dm.Qname, c.qnamesNxd[dm.Qname])
	}

	if dm.Latency > c.config.Subprocessors.Statistics.ThresholdSlow {
		if _, ok := c.qnamesSlow[dm.Qname]; !ok {
			c.qnamesSlow[dm.Qname] = 1
		} else {
			c.qnamesSlow[dm.Qname]++
		}
		c.qnamesSlowtop.Record(dm.Qname, c.qnamesSlow[dm.Qname])
	}

	// record all clients
	if _, ok := c.clients[dm.QueryIp]; !ok {
		c.clients[dm.QueryIp] = 1
	} else {
		c.clients[dm.QueryIp]++
	}
	c.clientstop.Record(dm.QueryIp, c.clients[dm.QueryIp])

	// record rrtypes
	if _, ok := c.rrtypes[dm.Qtype]; !ok {
		c.rrtypes[dm.Qtype] = 1
	} else {
		c.rrtypes[dm.Qtype]++
	}
	c.rrtypestop.Record(dm.Qtype, c.rrtypes[dm.Qtype])

	// record rcodes
	if _, ok := c.rcodes[dm.Rcode]; !ok {
		c.rcodes[dm.Rcode] = 1
	} else {
		c.rcodes[dm.Rcode]++
	}
	c.rcodestop.Record(dm.Rcode, c.rcodes[dm.Rcode])

	// recodes operations
	if _, ok := c.operations[dm.Operation]; !ok {
		c.operations[dm.Operation] = 1
	} else {
		c.operations[dm.Operation]++
	}
	c.operationstop.Record(dm.Operation, c.operations[dm.Operation])
}

func (c *StatsPerStream) Compute() {
	c.Lock()
	defer c.Unlock()

	// compute pps
	if c.total.Packets > 0 && c.total.PacketsPrev > 0 {
		c.total.Pps = c.total.Packets - c.total.PacketsPrev
	}
	c.total.PacketsPrev = c.total.Packets
	if c.total.Pps > c.total.PpsMax {
		c.total.PpsMax = c.total.Pps
	}
}

func (c *StatsPerStream) GetCounters() (ret Counters) {
	c.RLock()
	defer c.RUnlock()

	return c.total
}

func (c *StatsPerStream) GetTotalDomains() (ret int) {
	c.RLock()
	defer c.RUnlock()

	return len(c.qnames)
}

func (c *StatsPerStream) GetTotalFirstLevelDomains() (ret int) {
	c.RLock()
	defer c.RUnlock()

	return len(c.firstleveldomains)
}

func (c *StatsPerStream) GetTotalNxdomains() (ret int) {
	c.RLock()
	defer c.RUnlock()

	return len(c.qnamesNxd)
}

func (c *StatsPerStream) GetTotalSlowdomains() (ret int) {
	c.RLock()
	defer c.RUnlock()

	return len(c.qnamesSlow)
}

func (c *StatsPerStream) GetTotalSuspiciousdomains() (ret int) {
	c.RLock()
	defer c.RUnlock()

	return len(c.qnamesSuspicious)
}

func (c *StatsPerStream) GetTotalSuspiciousClients() (ret int) {
	c.RLock()
	defer c.RUnlock()

	return len(c.clientsSuspicious)
}

func (c *StatsPerStream) GetTotalClients() (ret int) {
	c.RLock()
	defer c.RUnlock()

	return len(c.clients)
}

func (c *StatsPerStream) GetTopQnames() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.qnamestop.Get()
}

func (c *StatsPerStream) GetTopFirstLevelDomains() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.firstleveldomainstop.Get()
}

func (c *StatsPerStream) GetTopNxdomains() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.qnamesNxdtop.Get()
}

func (c *StatsPerStream) GetTopSlowdomains() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.qnamesSlowtop.Get()
}

func (c *StatsPerStream) GetTopSuspiciousdomains() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.qnamesSuspicioustop.Get()
}

func (c *StatsPerStream) GetTopSuspiciousClients() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.clientsSuspicioustop.Get()
}

func (c *StatsPerStream) GetTopClients() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.clientstop.Get()
}

func (c *StatsPerStream) GetTopRcodes() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.rcodestop.Get()
}

func (c *StatsPerStream) GetTopRrtypes() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.rrtypestop.Get()
}

func (c *StatsPerStream) GetTopOperations() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.operationstop.Get()
}

func (c *StatsPerStream) GetTopTransports() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.transportstop.Get()
}

func (c *StatsPerStream) GetTopIpProto() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.ipprototop.Get()
}
