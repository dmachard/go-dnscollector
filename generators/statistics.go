package generators

import (
	"sync"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
)

type Counters struct {
	pps uint64
	qps uint64
	rps uint64

	queries_prev uint64
	replies_prev uint64

	queries      uint64
	queries_ipv4 uint64
	queries_ipv6 uint64
	queries_udp  uint64
	queries_tcp  uint64
	queries_doh  uint64
	queries_dot  uint64

	replies      uint64
	replies_ipv4 uint64
	replies_ipv6 uint64
	replies_udp  uint64
	replies_tcp  uint64
	replies_doh  uint64
	replies_dot  uint64

	latency0_1      uint64
	latency1_10     uint64
	latency10_50    uint64
	latency50_100   uint64
	latency100_1000 uint64
	latency1000_inf uint64

	qtype_a     uint64
	qtype_aaaa  uint64
	qtype_cname uint64
	qtype_txt   uint64
	qtype_ptr   uint64
	qtype_soa   uint64
	qtype_ns    uint64
	qtype_srv   uint64
	qtype_other uint64

	rcode_noerror  uint64
	rcode_servfail uint64
	rcode_nxdomain uint64
	rcode_refused  uint64
	rcode_other    uint64
}

type Statistics struct {
	total         Counters
	qnames        map[string]int
	qnamestop     *common.TopMap
	clients       map[string]int
	clientstop    *common.TopMap
	rrtypes       map[string]int
	rrtypestop    *common.TopMap
	rcodes        map[string]int
	rcodestop     *common.TopMap
	operations    map[string]int
	operationstop *common.TopMap
	rw            sync.RWMutex
}

func NewStatistics(maxitems int) *Statistics {
	c := &Statistics{
		total:         Counters{},
		qnames:        make(map[string]int),
		qnamestop:     common.NewTopMap(maxitems),
		clients:       make(map[string]int),
		clientstop:    common.NewTopMap(maxitems),
		rrtypes:       make(map[string]int),
		rrtypestop:    common.NewTopMap(maxitems),
		rcodes:        make(map[string]int),
		rcodestop:     common.NewTopMap(maxitems),
		operations:    make(map[string]int),
		operationstop: common.NewTopMap(maxitems),
	}
	return c
}
func (c *Statistics) Record(dm dnsmessage.DnsMessage) {
	c.rw.Lock()

	if dm.Type == "query" {
		c.total.queries++

		// count number of ipv4 or ipv6
		if dm.Family == "INET" {
			c.total.queries_ipv4++
		} else {
			c.total.queries_ipv6++
		}

		//count number of udp or tcp
		switch dm.Protocol {
		case "UDP":
			c.total.queries_udp++
		case "TCP":
			c.total.queries_tcp++
		case "DOH":
			c.total.queries_doh++
		case "DOT":
			c.total.queries_dot++
		}

	}

	if dm.Type == "reply" {
		c.total.replies++

		// count number of ipv4 or ipv6
		if dm.Family == "INET" {
			c.total.replies_ipv4++
		} else {
			c.total.replies_ipv6++
		}

		//count number of udp or tcp
		switch dm.Protocol {
		case "UDP":
			c.total.replies_udp++
		case "TCP":
			c.total.replies_tcp++
		case "DOH":
			c.total.queries_doh++
		case "DOT":
			c.total.queries_dot++
		}

	}

	switch {
	case dm.Latency == 0.0:
		break
	case dm.Latency > 0.0 && dm.Latency <= 0.001:
		c.total.latency0_1++
	case 0.001 < dm.Latency && dm.Latency <= 0.010:
		c.total.latency1_10++
	case 0.010 < dm.Latency && dm.Latency <= 0.050:
		c.total.latency10_50++
	case 0.050 < dm.Latency && dm.Latency <= 0.100:
		c.total.latency50_100++
	case 0.100 < dm.Latency && dm.Latency <= 1.000:
		c.total.latency100_1000++
	default:
		c.total.latency1000_inf++
	}

	switch {
	case dm.Qtype == "A":
		c.total.qtype_a++
	case dm.Qtype == "AAAA":
		c.total.qtype_aaaa++
	case dm.Qtype == "CNAME":
		c.total.qtype_cname++
	case dm.Qtype == "TXT":
		c.total.qtype_txt++
	case dm.Qtype == "PTR":
		c.total.qtype_ptr++
	case dm.Qtype == "SOA":
		c.total.qtype_soa++
	case dm.Qtype == "NS":
		c.total.qtype_ns++
	case dm.Qtype == "SRV":
		c.total.qtype_srv++
	default:
		c.total.qtype_other++
	}

	switch {
	case dm.Rcode == "NOERROR":
		c.total.rcode_noerror++
	case dm.Rcode == "SERVFAIL":
		c.total.rcode_servfail++
	case dm.Rcode == "NXDOMAIN":
		c.total.rcode_nxdomain++
	case dm.Rcode == "REFUSED":
		c.total.rcode_refused++
	default:
		c.total.rcode_other++
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
	if c.total.queries > 0 && c.total.queries_prev > 0 {
		c.total.qps = c.total.queries - c.total.queries_prev
	}
	c.total.queries_prev = c.total.queries

	// compute rps
	if c.total.replies > 0 && c.total.replies_prev > 0 {
		c.total.rps = c.total.replies - c.total.replies_prev
	}
	c.total.replies_prev = c.total.replies

	// total pps
	c.total.pps = c.total.qps + c.total.rps

	c.rw.Unlock()
}

func (c *Statistics) Get() (ret Counters) {
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
