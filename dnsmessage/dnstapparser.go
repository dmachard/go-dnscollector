package dnsmessage

import (
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

/*

dnstap decoder from one channel to dnsmessage in N channels

                                                 |---> channel 1 (dnsmessage)
dnstap --> channel in -> --- (dnstapdecoder)-----|---> channel 2
                                                 |---> channel n

*/

type DnstapConsumer struct {
	done      chan bool
	recv_from chan []byte
	logger    *logger.Logger
}

func NewDnstapConsumer(logger *logger.Logger) DnstapConsumer {
	logger.Info("dnstap consumer - initialization...")
	d := DnstapConsumer{
		done:      make(chan bool),
		recv_from: make(chan []byte, 512),
		logger:    logger,
	}
	return d
}

func (d *DnstapConsumer) GetChannel() chan []byte {
	return d.recv_from
}

func (d *DnstapConsumer) Stop() {
	close(d.recv_from)

	// read done channel and block until run is terminated
	<-d.done
	close(d.done)
}

func (d *DnstapConsumer) Run(send_to []chan DnsMessage) {

	dt := &dnstap.Dnstap{}
	cache_ttl := NewCacheDns(10 * time.Second)

	for data := range d.recv_from {

		err := proto.Unmarshal(data, dt)
		if err != nil {
			continue
		}

		dm := DnsMessage{}
		dm.Init()

		identity := dt.GetIdentity()
		if len(identity) > 0 {
			dm.Identity = string(identity)
		}

		dm.Operation = dt.GetMessage().GetType().String()
		dm.Family = dt.GetMessage().GetSocketFamily().String()
		dm.Protocol = dt.GetMessage().GetSocketProtocol().String()

		// decode query address and port
		queryip := dt.GetMessage().GetQueryAddress()
		if len(queryip) > 0 {
			dm.QueryIp = net.IP(queryip).String()
		}
		queryport := dt.GetMessage().GetQueryPort()
		if queryport > 0 {
			dm.QueryPort = strconv.FormatUint(uint64(queryport), 10)
		}

		// decode response address and port
		responseip := dt.GetMessage().GetResponseAddress()
		if len(responseip) > 0 {
			dm.ResponseIp = net.IP(responseip).String()
		}
		responseport := dt.GetMessage().GetResponsePort()
		if responseport > 0 {
			dm.ResponsePort = strconv.FormatUint(uint64(responseport), 10)
		}

		// get dns payload and timestamp according to the type (query or response)
		op := dnstap.Message_Type_value[dm.Operation]
		if op%2 == 1 {
			dns_payload := dt.GetMessage().GetQueryMessage()
			dm.Payload = dns_payload
			dm.Length = len(dns_payload)
			dm.Type = "query"
			dm.TimeSec = int(dt.GetMessage().GetQueryTimeSec())
			dm.TimeNsec = int(dt.GetMessage().GetQueryTimeNsec())
		} else {
			dns_payload := dt.GetMessage().GetResponseMessage()
			dm.Payload = dns_payload
			dm.Length = len(dns_payload)
			dm.Type = "reply"
			dm.TimeSec = int(dt.GetMessage().GetResponseTimeSec())
			dm.TimeNsec = int(dt.GetMessage().GetResponseTimeNsec())
		}

		// compute timestamp
		dm.Timestamp = float64(dm.TimeSec) + float64(dm.TimeNsec)/1e9

		// decode the dns payload to get id, rcode and the number of question
		// number of answer, ignore invalid packet
		dns_id, dns_rcode, dns_qdcount, dns_ancount, err := DecodeDns(dm.Payload)
		if err != nil {
			d.logger.Error("dns parser error: %s", err)
			continue
		}

		dm.Id = dns_id
		dm.Rcode = RcodeToString(dns_rcode)

		// continue to decode the dns payload to extract the qname and rrtype
		var dns_offsetrr int
		if dns_qdcount > 0 {
			dns_qname, dns_rrtype, offsetrr := DecodeQuestion(dm.Payload)
			dm.Qname = dns_qname
			dm.Qtype = RdatatypeToString(dns_rrtype)
			dns_offsetrr = offsetrr
		}

		if dns_ancount > 0 {
			dm.Answers = DecodeAnswer(dns_ancount, dns_offsetrr, dm.Payload)
		}

		// compute latency if possible
		if len(queryip) > 0 && queryport > 0 {
			// compute the hash of the query
			hash_data := []string{dm.QueryIp, dm.QueryPort, strconv.Itoa(dm.Id)}

			hashfnv := fnv.New64a()
			hashfnv.Write([]byte(strings.Join(hash_data[:], "+")))

			if dm.Type == "query" {
				cache_ttl.Set(hashfnv.Sum64(), dm.Timestamp)
			} else {
				value, ok := cache_ttl.Get(hashfnv.Sum64())
				if ok {
					dm.Latency = dm.Timestamp - value
				}
			}
		}

		dm.LatencySec = fmt.Sprintf("%.6f", dm.Latency)
		for i := range send_to {
			send_to[i] <- dm
		}
	}

	// dnstap channel consumer closed
	d.done <- true
}
