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

	Queries uint64
	Replies uint64

	Latency0_1      uint64
	Latency1_10     uint64
	Latency10_50    uint64
	Latency50_100   uint64
	Latency100_1000 uint64
	Latency1000_inf uint64
}

type Statistics struct {
	total         Counters
	qnames        map[string]int
	qnamestop     *topmap.TopMap
	clients       map[string]int
	clientstop    *topmap.TopMap
	rrtypes       map[string]int
	rrtypestop    *topmap.TopMap
	rcodes        map[string]int
	rcodestop     *topmap.TopMap
	operations    map[string]int
	operationstop *topmap.TopMap
	transports    map[string]int
	transportstop *topmap.TopMap
	ipproto       map[string]int
	ipprototop    *topmap.TopMap
	rw            sync.RWMutex
}

func NewStatistics(maxitems int) *Statistics {
	c := &Statistics{
		total:         Counters{},
		qnames:        make(map[string]int),
		qnamestop:     topmap.NewTopMap(maxitems),
		clients:       make(map[string]int),
		clientstop:    topmap.NewTopMap(maxitems),
		rrtypes:       make(map[string]int),
		rrtypestop:    topmap.NewTopMap(maxitems),
		rcodes:        make(map[string]int),
		rcodestop:     topmap.NewTopMap(maxitems),
		operations:    make(map[string]int),
		operationstop: topmap.NewTopMap(maxitems),
		transports:    make(map[string]int),
		transportstop: topmap.NewTopMap(maxitems),
		ipproto:       make(map[string]int),
		ipprototop:    topmap.NewTopMap(maxitems),
	}
	return c
}

func (c *Statistics) Record(dm DnsMessage) {
	c.rw.Lock()

	c.total.Packets++

	if dm.Type == "query" {
		c.total.Queries++
	} else {
		c.total.Replies++
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
	case 0.100 < dm.Latency && dm.Latency <= 1.000:
		c.total.Latency100_1000++
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
