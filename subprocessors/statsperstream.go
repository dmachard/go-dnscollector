package subprocessors

import (
	"strings"
	"sync"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-topmap"
)

type Counters struct {
	Pps              uint64
	PpsMax           uint64
	Packets          uint64
	PacketsPrev      uint64
	PacketsMalformed uint64

	Qps         uint64
	QpsMax      uint64
	Queries     uint64
	QueriesPrev uint64

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

	Truncated           int
	AuthoritativeAnswer int
	RecursionAvailable  int
	AuthenticData       int
}

type StatsPerStream struct {
	name   string
	config *dnsutils.Config

	total Counters

	firstleveldomains    map[string]int
	firstleveldomainstop *topmap.TopMap

	qnames    map[string]int
	qnamestop *topmap.TopMap

	qnamesNxd    map[string]int
	qnamesNxdtop *topmap.TopMap

	qnamesSlow    map[string]int
	qnamesSlowtop *topmap.TopMap

	qnamesSuspicious    map[string]int
	qnamesSuspicioustop *topmap.TopMap

	clients    map[string]int
	clientstop *topmap.TopMap

	clientsSuspicious    map[string]int
	clientsSuspicioustop *topmap.TopMap

	rrtypes    map[string]int
	rrtypestop *topmap.TopMap

	rcodes    map[string]int
	rcodestop *topmap.TopMap

	operations    map[string]int
	operationstop *topmap.TopMap

	transports    map[string]int
	transportstop *topmap.TopMap

	ipproto    map[string]int
	ipprototop *topmap.TopMap

	MapHitAS  map[string]int
	MapAS     map[string]string
	ListTopAS *topmap.TopMap

	commonQtypes map[string]bool
	sync.RWMutex
}

func NewStatsPerStream(config *dnsutils.Config, name string) *StatsPerStream {
	c := &StatsPerStream{
		name:   name,
		config: config,

		total: Counters{},

		MapHitAS:  make(map[string]int),
		MapAS:     make(map[string]string),
		ListTopAS: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		firstleveldomains:    make(map[string]int),
		firstleveldomainstop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		qnames:    make(map[string]int),
		qnamestop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		qnamesNxd:    make(map[string]int),
		qnamesNxdtop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		qnamesSlow:    make(map[string]int),
		qnamesSlowtop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		qnamesSuspicious:    make(map[string]int),
		qnamesSuspicioustop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		clients:    make(map[string]int),
		clientstop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		clientsSuspicious:    make(map[string]int),
		clientsSuspicioustop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		rrtypes:    make(map[string]int),
		rrtypestop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		rcodes:    make(map[string]int),
		rcodestop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		operations:    make(map[string]int),
		operationstop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		transports:    make(map[string]int),
		transportstop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		ipproto:    make(map[string]int),
		ipprototop: topmap.NewTopMap(config.Subprocessors.Statistics.TopMaxItems),

		commonQtypes: make(map[string]bool),
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
	if dm.DNS.MalformedPacket == 1 {
		c.total.PacketsMalformed++

		if _, ok := c.clientsSuspicious[dm.NetworkInfo.QueryIp]; !ok {
			c.clientsSuspicious[dm.NetworkInfo.QueryIp] = 1
		} else {
			c.clientsSuspicious[dm.NetworkInfo.QueryIp]++
		}
		c.clientsSuspicioustop.Record(dm.NetworkInfo.QueryIp, c.clientsSuspicious[dm.NetworkInfo.QueryIp])

		return
	}

	// packet size repartition
	if dm.DNS.Type == dnsutils.DnsQuery {
		c.total.Queries++
		c.total.ReceivedBytesTotal += dm.DNS.Length

		if c.total.QueryLengthMin == 0 {
			c.total.QueryLengthMin = dm.DNS.Length
		}

		// max value
		if dm.DNS.Length > c.total.QueryLengthMax {
			c.total.QueryLengthMax = dm.DNS.Length
		}
		// min value
		if dm.DNS.Length < c.total.QueryLengthMin {
			c.total.QueryLengthMin = dm.DNS.Length
		}

		switch {
		case dm.DNS.Length <= 50:
			c.total.QueryLength0_50++
		case 50 < dm.DNS.Length && dm.DNS.Length <= 100:
			c.total.QueryLength50_100++
		case 100 < dm.DNS.Length && dm.DNS.Length <= 250:
			c.total.QueryLength100_250++
		case 250 < dm.DNS.Length && dm.DNS.Length <= 500:
			c.total.QueryLength250_500++
		default:
			c.total.QueryLength500_Inf++
		}
	} else {
		c.total.SentBytesTotal += dm.DNS.Length

		if c.total.ReplyLengthMin == 0 {
			c.total.ReplyLengthMin = dm.DNS.Length
		}

		// max value
		if dm.DNS.Length > c.total.ReplyLengthMax {
			c.total.ReplyLengthMax = dm.DNS.Length
		}
		// min value
		if dm.DNS.Length < c.total.ReplyLengthMin {
			c.total.ReplyLengthMin = dm.DNS.Length
		}

		switch {
		case dm.DNS.Length <= 50:
			c.total.ReplyLength0_50++
		case 50 < dm.DNS.Length && dm.DNS.Length <= 100:
			c.total.ReplyLength50_100++
		case 100 < dm.DNS.Length && dm.DNS.Length <= 250:
			c.total.ReplyLength100_250++
		case 250 < dm.DNS.Length && dm.DNS.Length <= 500:
			c.total.ReplyLength250_500++
		default:
			c.total.ReplyLength500_Inf++
		}
	}

	// qname length
	qnameLen := len(dm.DNS.Qname)
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
		if _, ok := c.qnamesSuspicious[dm.DNS.Qname]; !ok {
			c.qnamesSuspicious[dm.DNS.Qname] = 1
		} else {
			c.qnamesSuspicious[dm.DNS.Qname]++
		}
		c.qnamesSuspicioustop.Record(dm.DNS.Qname, c.qnamesSuspicious[dm.DNS.Qname])

		if _, ok := c.clientsSuspicious[dm.NetworkInfo.QueryIp]; !ok {
			c.clientsSuspicious[dm.NetworkInfo.QueryIp] = 1
		} else {
			c.clientsSuspicious[dm.NetworkInfo.QueryIp]++
		}
		c.clientsSuspicioustop.Record(dm.NetworkInfo.QueryIp, c.clientsSuspicious[dm.NetworkInfo.QueryIp])
	}

	if _, found := c.commonQtypes[dm.DNS.Qtype]; !found {
		if _, ok := c.qnamesSuspicious[dm.DNS.Qname]; !ok {
			c.qnamesSuspicious[dm.DNS.Qname] = 1
		} else {
			c.qnamesSuspicious[dm.DNS.Qname]++
		}
		c.qnamesSuspicioustop.Record(dm.DNS.Qname, c.qnamesSuspicious[dm.DNS.Qname])

		if _, ok := c.clientsSuspicious[dm.NetworkInfo.QueryIp]; !ok {
			c.clientsSuspicious[dm.NetworkInfo.QueryIp] = 1
		} else {
			c.clientsSuspicious[dm.NetworkInfo.QueryIp]++
		}
		c.clientsSuspicioustop.Record(dm.NetworkInfo.QueryIp, c.clientsSuspicious[dm.NetworkInfo.QueryIp])
	}

	if dm.DNS.Length >= c.config.Subprocessors.Statistics.ThresholdPacketLen {
		if _, ok := c.qnamesSuspicious[dm.DNS.Qname]; !ok {
			c.qnamesSuspicious[dm.DNS.Qname] = 1
		} else {
			c.qnamesSuspicious[dm.DNS.Qname]++
		}
		c.qnamesSuspicioustop.Record(dm.DNS.Qname, c.qnamesSuspicious[dm.DNS.Qname])

		if _, ok := c.clientsSuspicious[dm.NetworkInfo.QueryIp]; !ok {
			c.clientsSuspicious[dm.NetworkInfo.QueryIp] = 1
		} else {
			c.clientsSuspicious[dm.NetworkInfo.QueryIp]++
		}
		c.clientsSuspicioustop.Record(dm.NetworkInfo.QueryIp, c.clientsSuspicious[dm.NetworkInfo.QueryIp])
	}

	// latency
	if dm.DnsTap.Latency > c.total.LatencyMax {
		c.total.LatencyMax = dm.DnsTap.Latency
	}

	if dm.DnsTap.Latency > 0.0 {
		if c.total.LatencyMin == 0.0 {
			c.total.LatencyMin = dm.DnsTap.Latency
		}
		if dm.DnsTap.Latency < c.total.LatencyMin {
			c.total.LatencyMin = dm.DnsTap.Latency
		}
	}

	switch {
	case dm.DnsTap.Latency == 0.0:
		break
	case dm.DnsTap.Latency > 0.0 && dm.DnsTap.Latency <= 0.001:
		c.total.Latency0_1++
	case 0.001 < dm.DnsTap.Latency && dm.DnsTap.Latency <= 0.010:
		c.total.Latency1_10++
	case 0.010 < dm.DnsTap.Latency && dm.DnsTap.Latency <= 0.050:
		c.total.Latency10_50++
	case 0.050 < dm.DnsTap.Latency && dm.DnsTap.Latency <= 0.100:
		c.total.Latency50_100++
	case 0.100 < dm.DnsTap.Latency && dm.DnsTap.Latency <= 0.500:
		c.total.Latency100_500++
	case 0.500 < dm.DnsTap.Latency && dm.DnsTap.Latency <= 1.000:
		c.total.Latency500_1000++
	default:
		c.total.Latency1000_inf++
	}

	// record ip proto
	if _, ok := c.ipproto[dm.NetworkInfo.Family]; !ok {
		c.ipproto[dm.NetworkInfo.Family] = 1
	} else {
		c.ipproto[dm.NetworkInfo.Family]++
	}
	c.ipprototop.Record(dm.NetworkInfo.Family, c.ipproto[dm.NetworkInfo.Family])

	// record transports
	if _, ok := c.transports[dm.NetworkInfo.Protocol]; !ok {
		c.transports[dm.NetworkInfo.Protocol] = 1
	} else {
		c.transports[dm.NetworkInfo.Protocol]++
	}
	c.transportstop.Record(dm.NetworkInfo.Protocol, c.transports[dm.NetworkInfo.Protocol])

	// record first level domain
	i := strings.LastIndex(dm.DNS.Qname, ".")
	if i > -1 {
		fld := dm.DNS.Qname[i+1:]
		if _, ok := c.firstleveldomains[fld]; !ok {
			c.firstleveldomains[fld] = 1
		} else {
			c.firstleveldomains[fld]++
		}
		c.firstleveldomainstop.Record(fld, c.firstleveldomains[fld])
	}

	// record all qnames
	if _, ok := c.qnames[dm.DNS.Qname]; !ok {
		c.qnames[dm.DNS.Qname] = 1
	} else {
		c.qnames[dm.DNS.Qname]++
	}
	c.qnamestop.Record(dm.DNS.Qname, c.qnames[dm.DNS.Qname])

	if dm.DNS.Rcode == "NXDOMAIN" {
		if _, ok := c.qnamesNxd[dm.DNS.Qname]; !ok {
			c.qnamesNxd[dm.DNS.Qname] = 1
		} else {
			c.qnamesNxd[dm.DNS.Qname]++
		}
		c.qnamesNxdtop.Record(dm.DNS.Qname, c.qnamesNxd[dm.DNS.Qname])
	}

	if dm.DnsTap.Latency > c.config.Subprocessors.Statistics.ThresholdSlow {
		if _, ok := c.qnamesSlow[dm.DNS.Qname]; !ok {
			c.qnamesSlow[dm.DNS.Qname] = 1
		} else {
			c.qnamesSlow[dm.DNS.Qname]++
		}
		c.qnamesSlowtop.Record(dm.DNS.Qname, c.qnamesSlow[dm.DNS.Qname])
	}

	// record all clients
	if _, ok := c.clients[dm.NetworkInfo.QueryIp]; !ok {
		c.clients[dm.NetworkInfo.QueryIp] = 1
	} else {
		c.clients[dm.NetworkInfo.QueryIp]++
	}
	c.clientstop.Record(dm.NetworkInfo.QueryIp, c.clients[dm.NetworkInfo.QueryIp])

	// record rrtypes
	if _, ok := c.rrtypes[dm.DNS.Qtype]; !ok {
		c.rrtypes[dm.DNS.Qtype] = 1
	} else {
		c.rrtypes[dm.DNS.Qtype]++
	}
	c.rrtypestop.Record(dm.DNS.Qtype, c.rrtypes[dm.DNS.Qtype])

	// record rcodes
	if _, ok := c.rcodes[dm.DNS.Rcode]; !ok {
		c.rcodes[dm.DNS.Rcode] = 1
	} else {
		c.rcodes[dm.DNS.Rcode]++
	}
	c.rcodestop.Record(dm.DNS.Rcode, c.rcodes[dm.DNS.Rcode])

	// record operations
	if _, ok := c.operations[dm.DnsTap.Operation]; !ok {
		c.operations[dm.DnsTap.Operation] = 1
	} else {
		c.operations[dm.DnsTap.Operation]++
	}
	c.operationstop.Record(dm.DnsTap.Operation, c.operations[dm.DnsTap.Operation])

	// dns flags
	if dm.DNS.Flags.TC {
		c.total.Truncated++
	}
	if dm.DNS.Flags.AA {
		c.total.AuthoritativeAnswer++
	}
	if dm.DNS.Flags.RA {
		c.total.RecursionAvailable++
	}
	if dm.DNS.Flags.AD {
		c.total.AuthenticData++
	}

	// as stats
	if _, ok := c.MapHitAS[dm.NetworkInfo.AutonomousSystemNumber]; !ok {
		c.MapHitAS[dm.NetworkInfo.AutonomousSystemNumber] = 1
	} else {
		c.MapHitAS[dm.NetworkInfo.AutonomousSystemNumber]++
	}
	// record as number with owner
	if _, ok := c.MapAS[dm.NetworkInfo.AutonomousSystemNumber]; !ok {
		c.MapAS[dm.NetworkInfo.AutonomousSystemNumber] = dm.NetworkInfo.AutonomousSystemOrg
	}
	c.ListTopAS.Record(dm.NetworkInfo.AutonomousSystemNumber, c.MapHitAS[dm.NetworkInfo.AutonomousSystemNumber])
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

	// compute qps
	if c.total.Queries > 0 && c.total.QueriesPrev > 0 {
		c.total.Qps = c.total.Queries - c.total.QueriesPrev
	}
	c.total.QueriesPrev = c.total.Queries
	if c.total.Qps > c.total.QpsMax {
		c.total.QpsMax = c.total.Qps
	}
}

func (c *StatsPerStream) Reset() {
	c.Lock()
	defer c.Unlock()

	c.total.AuthenticData = 0
	c.total.RecursionAvailable = 0
	c.total.AuthoritativeAnswer = 0
	c.total.Truncated = 0

	c.total.Qps = 0
	c.total.QpsMax = 0
	c.total.Queries = 0
	c.total.QueriesPrev = 0

	c.total.Pps = 0
	c.total.PpsMax = 0
	c.total.Packets = 0
	c.total.PacketsPrev = 0
	c.total.PacketsMalformed = 0
	c.total.ReceivedBytesTotal = 0
	c.total.SentBytesTotal = 0

	c.total.Latency0_1 = 0
	c.total.Latency1_10 = 0
	c.total.Latency10_50 = 0
	c.total.Latency50_100 = 0
	c.total.Latency100_500 = 0
	c.total.Latency1000_inf = 0
	c.total.LatencyMax = 0
	c.total.LatencyMin = 0

	c.total.QnameLength0_10 = 0
	c.total.QnameLength10_20 = 0
	c.total.QnameLength20_40 = 0
	c.total.QnameLength40_60 = 0
	c.total.QnameLength60_100 = 0
	c.total.QnameLength100_Inf = 0
	c.total.QnameLengthMax = 0
	c.total.QnameLengthMin = 0

	c.total.QueryLength0_50 = 0
	c.total.QueryLength50_100 = 0
	c.total.QueryLength100_250 = 0
	c.total.QueryLength250_500 = 0
	c.total.QueryLength500_Inf = 0
	c.total.QueryLengthMax = 0
	c.total.QueryLengthMin = 0

	c.total.ReplyLength0_50 = 0
	c.total.ReplyLength50_100 = 0
	c.total.ReplyLength100_250 = 0
	c.total.ReplyLength250_500 = 0
	c.total.ReplyLength500_Inf = 0
	c.total.ReplyLengthMin = 0
	c.total.ReplyLengthMax = 0

	c.firstleveldomains = make(map[string]int)
	c.firstleveldomainstop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.qnames = make(map[string]int)
	c.qnamestop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.qnamesNxd = make(map[string]int)
	c.qnamesNxdtop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.qnamesSlow = make(map[string]int)
	c.qnamesSlowtop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.qnamesSuspicious = make(map[string]int)
	c.qnamesSuspicioustop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.clients = make(map[string]int)
	c.clientstop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.clientsSuspicious = make(map[string]int)
	c.clientsSuspicioustop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.rrtypes = make(map[string]int)
	c.rrtypestop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.rcodes = make(map[string]int)
	c.rcodestop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.operations = make(map[string]int)
	c.operationstop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.transports = make(map[string]int)
	c.transportstop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.ipproto = make(map[string]int)
	c.ipprototop = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)

	c.MapHitAS = make(map[string]int)
	c.MapAS = make(map[string]string)
	c.ListTopAS = topmap.NewTopMap(c.config.Subprocessors.Statistics.TopMaxItems)
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

func (c *StatsPerStream) GetTotalAS() (ret int) {
	c.RLock()
	defer c.RUnlock()

	return len(c.MapHitAS)
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

func (c *StatsPerStream) GetTopAS() (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.ListTopAS.Get()
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

func (c *StatsPerStream) GetClients() (ret map[string]int) {
	c.RLock()
	defer c.RUnlock()

	retMap := map[string]int{}
	for k, v := range c.clients {
		retMap[k] = v
	}

	return retMap
}

func (c *StatsPerStream) GetDomains() (ret map[string]int) {
	c.RLock()
	defer c.RUnlock()

	retMap := map[string]int{}
	for k, v := range c.qnames {
		retMap[k] = v
	}

	return retMap
}

func (c *StatsPerStream) GetHitAS() (ret map[string]int) {
	c.RLock()
	defer c.RUnlock()

	retMap := map[string]int{}
	for k, v := range c.MapHitAS {
		retMap[k] = v
	}

	return retMap
}

func (c *StatsPerStream) GetAS() (ret map[string]string) {
	c.RLock()
	defer c.RUnlock()

	retMap := map[string]string{}
	for k, v := range c.MapAS {
		retMap[k] = v
	}

	return retMap
}
