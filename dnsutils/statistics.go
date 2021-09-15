package dnsutils

import (
	"sync"

	"github.com/dmachard/go-topmap"
)

type Counters struct {
	Pps     uint64
	Pps_max uint64
	Qps     uint64
	Qps_max uint64
	Rps     uint64
	Rps_max uint64

	Queries_prev uint64
	Replies_prev uint64

	Queries      uint64
	Queries_ipv4 uint64
	Queries_ipv6 uint64
	Queries_udp  uint64
	Queries_tcp  uint64
	Queries_doh  uint64
	Queries_dot  uint64

	Replies      uint64
	Replies_ipv4 uint64
	Replies_ipv6 uint64
	Replies_udp  uint64
	Replies_tcp  uint64
	Replies_doh  uint64
	Replies_dot  uint64

	Latency0_1      uint64
	Latency1_10     uint64
	Latency10_50    uint64
	Latency50_100   uint64
	Latency100_1000 uint64
	Latency1000_inf uint64

	Qtype_a     uint64
	Qtype_aaaa  uint64
	Qtype_cname uint64
	Qtype_txt   uint64
	Qtype_ptr   uint64
	Qtype_soa   uint64
	Qtype_ns    uint64
	Qtype_srv   uint64
	Qtype_other uint64

	Rcode_noerror  uint64
	Rcode_servfail uint64
	Rcode_nxdomain uint64
	Rcode_refused  uint64
	Rcode_notimp   uint64
	Rcode_other    uint64
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
	}
	return c
}

func (c *Statistics) Record(dm DnsMessage) {
	c.rw.Lock()

	if dm.Type == "query" {
		c.total.Queries++

		// count number of ipv4 or ipv6
		if dm.Family == "INET" {
			c.total.Queries_ipv4++
		} else {
			c.total.Queries_ipv6++
		}

		//count number of udp or tcp
		switch dm.Protocol {
		case "UDP":
			c.total.Queries_udp++
		case "TCP":
			c.total.Queries_tcp++
		case "DOH":
			c.total.Queries_doh++
		case "DOT":
			c.total.Queries_dot++
		}

	}

	if dm.Type == "reply" {
		c.total.Replies++

		// count number of ipv4 or ipv6
		if dm.Family == "INET" {
			c.total.Replies_ipv4++
		} else {
			c.total.Replies_ipv6++
		}

		//count number of udp or tcp
		switch dm.Protocol {
		case "UDP":
			c.total.Replies_udp++
		case "TCP":
			c.total.Replies_tcp++
		case "DOH":
			c.total.Queries_doh++
		case "DOT":
			c.total.Queries_dot++
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
	case 0.100 < dm.Latency && dm.Latency <= 1.000:
		c.total.Latency100_1000++
	default:
		c.total.Latency1000_inf++
	}

	switch {
	case dm.Qtype == "A":
		c.total.Qtype_a++
	case dm.Qtype == "AAAA":
		c.total.Qtype_aaaa++
	case dm.Qtype == "CNAME":
		c.total.Qtype_cname++
	case dm.Qtype == "TXT":
		c.total.Qtype_txt++
	case dm.Qtype == "PTR":
		c.total.Qtype_ptr++
	case dm.Qtype == "SOA":
		c.total.Qtype_soa++
	case dm.Qtype == "NS":
		c.total.Qtype_ns++
	case dm.Qtype == "SRV":
		c.total.Qtype_srv++
	default:
		c.total.Qtype_other++
	}

	switch {
	case dm.Rcode == "NOERROR":
		c.total.Rcode_noerror++
	case dm.Rcode == "SERVFAIL":
		c.total.Rcode_servfail++
	case dm.Rcode == "NXDOMAIN":
		c.total.Rcode_nxdomain++
	case dm.Rcode == "REFUSED":
		c.total.Rcode_refused++
	case dm.Rcode == "NOTIMP":
		c.total.Rcode_notimp++
	default:
		c.total.Rcode_other++
	}

	// record all qnames
	if _, ok := c.qnames[dm.Qname]; !ok {
		c.qnames[dm.Qname] = 1
	} else {
		c.qnames[dm.Qname]++
	}

	// record top qnames
	c.qnamestop.Record(dm.Qname, c.qnames[dm.Qname])

	// record all clients
	if _, ok := c.clients[dm.QueryIp]; !ok {
		c.clients[dm.QueryIp] = 1
	} else {
		c.clients[dm.QueryIp]++
	}

	// record top clients
	c.clientstop.Record(dm.QueryIp, c.clients[dm.QueryIp])

	// record rrtypes
	if _, ok := c.rrtypes[dm.Qtype]; !ok {
		c.rrtypes[dm.Qtype] = 1
	} else {
		c.rrtypes[dm.Qtype]++
	}
	// record top rrtypes
	c.rrtypestop.Record(dm.Qtype, c.rrtypes[dm.Qtype])

	// record rcodes
	if _, ok := c.rcodes[dm.Rcode]; !ok {
		c.rcodes[dm.Rcode] = 1
	} else {
		c.rcodes[dm.Rcode]++
	}
	// record top rcodes
	c.rcodestop.Record(dm.Rcode, c.rcodes[dm.Rcode])

	// recodes operations
	if _, ok := c.operations[dm.Operation]; !ok {
		c.operations[dm.Operation] = 1
	} else {
		c.operations[dm.Operation]++
	}
	// record top operations
	c.operationstop.Record(dm.Operation, c.operations[dm.Operation])

	c.rw.Unlock()
}

func (c *Statistics) Compute() {
	c.rw.Lock()

	//compute qps
	if c.total.Queries > 0 && c.total.Queries_prev > 0 {
		c.total.Qps = c.total.Queries - c.total.Queries_prev
	}
	c.total.Queries_prev = c.total.Queries
	if c.total.Qps > c.total.Qps_max {
		c.total.Qps_max = c.total.Qps
	}

	// compute rps
	if c.total.Replies > 0 && c.total.Replies_prev > 0 {
		c.total.Rps = c.total.Replies - c.total.Replies_prev
	}
	c.total.Replies_prev = c.total.Replies
	if c.total.Rps > c.total.Rps_max {
		c.total.Rps_max = c.total.Rps
	}

	// total pps
	c.total.Pps = c.total.Qps + c.total.Rps
	if c.total.Pps > c.total.Pps_max {
		c.total.Pps_max = c.total.Pps
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
