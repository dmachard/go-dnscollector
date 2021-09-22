package dnsutils

import (
	"sync"

	"github.com/dmachard/go-topmap"
)

type Counters struct {
	Pps    uint64
	PpsMax uint64

	Packets     uint64
	PacketsPrev uint64

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
}

type Statistics struct {
	total               Counters
	qnames              map[string]int
	qnamestop           *topmap.TopMap
	qnamesNxd           map[string]int
	qnamesNxdtop        *topmap.TopMap
	qnamesSlow          map[string]int
	qnamesSlowtop       *topmap.TopMap
	qnamesSuspicious    map[string]int
	qnamesSuspicioustop *topmap.TopMap
	clients             map[string]int
	clientstop          *topmap.TopMap
	rrtypes             map[string]int
	rrtypestop          *topmap.TopMap
	rcodes              map[string]int
	rcodestop           *topmap.TopMap
	operations          map[string]int
	operationstop       *topmap.TopMap
	transports          map[string]int
	transportstop       *topmap.TopMap
	ipproto             map[string]int
	ipprototop          *topmap.TopMap
	commonQtypes        map[string]bool
	rw                  sync.RWMutex
}

func NewStatistics(maxitems int) *Statistics {
	c := &Statistics{
		total:               Counters{},
		qnames:              make(map[string]int),
		qnamestop:           topmap.NewTopMap(maxitems),
		qnamesNxd:           make(map[string]int),
		qnamesNxdtop:        topmap.NewTopMap(maxitems),
		qnamesSlow:          make(map[string]int),
		qnamesSlowtop:       topmap.NewTopMap(maxitems),
		qnamesSuspicious:    make(map[string]int),
		qnamesSuspicioustop: topmap.NewTopMap(maxitems),
		clients:             make(map[string]int),
		clientstop:          topmap.NewTopMap(maxitems),
		rrtypes:             make(map[string]int),
		rrtypestop:          topmap.NewTopMap(maxitems),
		rcodes:              make(map[string]int),
		rcodestop:           topmap.NewTopMap(maxitems),
		operations:          make(map[string]int),
		operationstop:       topmap.NewTopMap(maxitems),
		transports:          make(map[string]int),
		transportstop:       topmap.NewTopMap(maxitems),
		ipproto:             make(map[string]int),
		ipprototop:          topmap.NewTopMap(maxitems),
		commonQtypes:        make(map[string]bool),
	}
	c.commonQtypes = map[string]bool{"A": true, "AAAA": true, "TXT": true,
		"CNAME": true, "PTR": true, "NAPTR": true,
		"DNSKEY": true, "SRV": true}
	return c
}

func (c *Statistics) Record(dm DnsMessage) {
	c.rw.Lock()

	// global number of packets
	c.total.Packets++

	// packet size repartition
	if dm.Type == "query" {
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
	if qnameLen >= 80 {
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

	if dm.Latency > 0.5 {
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

	c.rw.Unlock()
}

func (c *Statistics) Compute() {
	c.rw.Lock()

	// compute pps
	if c.total.Packets > 0 && c.total.PacketsPrev > 0 {
		c.total.Pps = c.total.Packets - c.total.PacketsPrev
	}
	c.total.PacketsPrev = c.total.Packets
	if c.total.Pps > c.total.PpsMax {
		c.total.PpsMax = c.total.Pps
	}

	c.rw.Unlock()
}

func (c *Statistics) GetCounters() (ret Counters) {
	c.rw.RLock()
	ret = c.total
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTotalDomains() (ret int) {
	c.rw.RLock()
	ret = len(c.qnames)
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTotalNxdomains() (ret int) {
	c.rw.RLock()
	ret = len(c.qnamesNxd)
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTotalSlowdomains() (ret int) {
	c.rw.RLock()
	ret = len(c.qnamesSlow)
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTotalSuspiciousdomains() (ret int) {
	c.rw.RLock()
	ret = len(c.qnamesSuspicious)
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTotalClients() (ret int) {
	c.rw.RLock()
	ret = len(c.clients)
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopQnames() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.qnamestop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopNxdomains() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.qnamesNxdtop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopSlowdomains() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.qnamesSlowtop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopSuspiciousdomains() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.qnamesSuspicioustop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopClients() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.clientstop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopRcodes() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.rcodestop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopRrtypes() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.rrtypestop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopOperations() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.operationstop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopTransports() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.transportstop.Get()
	c.rw.RUnlock()
	return
}

func (c *Statistics) GetTopIpProto() (ret []topmap.TopMapItem) {
	c.rw.RLock()
	ret = c.ipprototop.Get()
	c.rw.RUnlock()
	return
}

type GlobalStats struct {
	stats    map[string]*Statistics
	maxitems int
	sync.RWMutex
}

func NewGlobalStats(maxitems int) *GlobalStats {
	c := &GlobalStats{
		stats: make(map[string]*Statistics),
	}
	c.maxitems = maxitems
	c.stats["global"] = NewStatistics(maxitems)
	return c
}

func (c *GlobalStats) Record(dm DnsMessage) {
	c.Lock()
	defer c.Unlock()

	// global record
	c.stats["global"].Record(dm)

	// record for each ident
	if _, ok := c.stats[dm.Identity]; !ok {
		c.stats[dm.Identity] = NewStatistics(c.maxitems)
	}
	c.stats[dm.Identity].Record(dm)

}

func (c *GlobalStats) Streams() []string {
	c.RLock()
	defer c.RUnlock()

	ret := []string{}
	for k, _ := range c.stats {
		ret = append(ret, k)
	}
	return ret
}

func (c *GlobalStats) Compute() {
	c.Lock()
	for _, v := range c.stats {
		v.Compute()
	}
	c.Unlock()
}

func (c *GlobalStats) GetCounters(identity string) (ret Counters) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetCounters()
}

func (c *GlobalStats) GetTotalDomains(identity string) (ret int) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTotalDomains()
}

func (c *GlobalStats) GetTotalNxdomains(identity string) (ret int) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTotalNxdomains()
}

func (c *GlobalStats) GetTotalSlowdomains(identity string) (ret int) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTotalSlowdomains()
}

func (c *GlobalStats) GetTotalSuspiciousdomains(identity string) (ret int) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTotalSuspiciousdomains()
}

func (c *GlobalStats) GetTotalClients(identity string) (ret int) {
	c.RLock()
	defer c.RUnlock()

	v, found := c.stats[identity]
	if !found {
		return 0
	}
	return v.GetTotalClients()
}

func (c *GlobalStats) GetTopQnames(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	v, found := c.stats[identity]
	if !found {
		return []topmap.TopMapItem{}
	}

	return v.GetTopQnames()
}

func (c *GlobalStats) GetTopNxdomains(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	v, found := c.stats[identity]
	if !found {
		return []topmap.TopMapItem{}
	}

	return v.GetTopNxdomains()
}

func (c *GlobalStats) GetTopSlowdomains(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	v, found := c.stats[identity]
	if !found {
		return []topmap.TopMapItem{}
	}

	return v.GetTopSlowdomains()
}

func (c *GlobalStats) GetTopSuspiciousdomains(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	v, found := c.stats[identity]
	if !found {
		return []topmap.TopMapItem{}
	}

	return v.GetTopSuspiciousdomains()
}

func (c *GlobalStats) GetTopClients(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	v, found := c.stats[identity]
	if !found {
		return []topmap.TopMapItem{}
	}

	return v.GetTopClients()
}

func (c *GlobalStats) GetTopRcodes(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTopRcodes()
}

func (c *GlobalStats) GetTopRrtypes(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTopRrtypes()
}

func (c *GlobalStats) GetTopOperations(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTopOperations()
}

func (c *GlobalStats) GetTopTransports(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTopTransports()
}

func (c *GlobalStats) GetTopIpProto(identity string) (ret []topmap.TopMapItem) {
	c.RLock()
	defer c.RUnlock()

	return c.stats[identity].GetTopIpProto()
}
