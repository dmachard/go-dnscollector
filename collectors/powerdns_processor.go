package collectors

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"google.golang.org/protobuf/proto"
)

var (
	PdnsQr = map[string]string{
		"DNSQueryType":    "Q",
		"DNSResponseType": "R",
	}
)

type PdnsProcessor struct {
	done     chan bool
	recvFrom chan []byte
	logger   *logger.Logger
	config   *dnsutils.Config
	name     string
}

func NewPdnsProcessor(config *dnsutils.Config, logger *logger.Logger, name string) PdnsProcessor {
	logger.Info("[%s] powerdns processor - initialization...", name)
	d := PdnsProcessor{
		done:     make(chan bool),
		recvFrom: make(chan []byte, 512),
		logger:   logger,
		config:   config,
		name:     name,
	}

	d.ReadConfig()

	return d
}

func (c *PdnsProcessor) ReadConfig() {
	c.logger.Info("[" + c.name + "] processor powerdns parser - config")
}

func (c *PdnsProcessor) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] processor powerdns parser - "+msg, v...)
}

func (c *PdnsProcessor) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] procesor powerdns parser - "+msg, v...)
}

func (d *PdnsProcessor) GetChannel() chan []byte {
	return d.recvFrom
}

func (d *PdnsProcessor) Stop() {
	close(d.recvFrom)

	// read done channel and block until run is terminated
	<-d.done
	close(d.done)
}

func (d *PdnsProcessor) Run(sendTo []chan dnsutils.DnsMessage) {

	pbdm := &powerdns_protobuf.PBDNSMessage{}

	// prepare enabled transformers
	subprocessors := transformers.NewTransforms(&d.config.IngoingTransformers, d.logger, d.name)

	// read incoming dns message
	d.LogInfo("running... waiting incoming dns message")
	for data := range d.recvFrom {
		err := proto.Unmarshal(data, pbdm)
		if err != nil {
			continue
		}

		dm := dnsutils.DnsMessage{}
		dm.Init()

		dm.DnsTap.Identity = string(pbdm.GetServerIdentity())
		dm.DnsTap.Operation = pbdm.GetType().String()

		dm.NetworkInfo.Family = pbdm.GetSocketFamily().String()
		dm.NetworkInfo.Protocol = pbdm.GetSocketProtocol().String()

		if pbdm.From != nil {
			dm.NetworkInfo.QueryIp = net.IP(pbdm.From).String()
		}
		dm.NetworkInfo.QueryPort = strconv.FormatUint(uint64(pbdm.GetFromPort()), 10)
		dm.NetworkInfo.ResponseIp = net.IP(pbdm.To).String()
		dm.NetworkInfo.ResponsePort = strconv.FormatUint(uint64(pbdm.GetToPort()), 10)

		dm.DNS.Id = int(pbdm.GetId())
		dm.DNS.Length = int(pbdm.GetInBytes())
		dm.DnsTap.TimeSec = int(pbdm.GetTimeSec())
		dm.DnsTap.TimeNsec = int(pbdm.GetTimeUsec())

		if int(pbdm.Type.Number())%2 == 1 {
			dm.DNS.Type = dnsutils.DnsQuery
		} else {
			dm.DNS.Type = dnsutils.DnsReply

			tsQuery := float64(pbdm.Response.GetQueryTimeSec()) + float64(pbdm.Response.GetQueryTimeUsec())/1e6
			tsReply := float64(pbdm.GetTimeSec()) + float64(pbdm.GetTimeUsec())/1e6

			// convert latency to human
			dm.DnsTap.Latency = tsReply - tsQuery
			dm.DnsTap.LatencySec = fmt.Sprintf("%.6f", dm.DnsTap.Latency)
			dm.DNS.Rcode = dnsutils.RcodeToString(int(pbdm.Response.GetRcode()))

		}

		// compute timestamp
		dm.DnsTap.Timestamp = float64(dm.DnsTap.TimeSec) + float64(dm.DnsTap.TimeNsec)/1e9
		ts := time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))
		dm.DnsTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

		dm.DNS.Qname = pbdm.Question.GetQName()
		// remove ending dot ?
		dm.DNS.Qname = strings.TrimSuffix(dm.DNS.Qname, ".")

		// get query type
		dm.DNS.Qtype = dnsutils.RdatatypeToString(int(pbdm.Question.GetQType()))

		// get specific powerdns params
		pdns := dnsutils.PowerDns{}

		// get PowerDNS OriginalRequestSubnet
		ip := pbdm.GetOriginalRequestorSubnet()
		if len(ip) == 4 {
			addr := make(net.IP, net.IPv4len)
			copy(addr, ip)
			pdns.OriginalRequestSubnet = addr.String()
		}
		if len(ip) == 16 {
			addr := make(net.IP, net.IPv6len)
			copy(addr, ip)
			pdns.OriginalRequestSubnet = addr.String()
		}

		// get PowerDNS tags
		tags := pbdm.GetResponse().GetTags()
		if tags == nil {
			tags = []string{}
		}
		pdns.Tags = tags

		// get PowerDNS policy applied
		pdns.AppliedPolicy = pbdm.GetResponse().GetAppliedPolicy()

		dm.PowerDns = pdns

		// decode answers
		answers := []dnsutils.DnsAnswer{}
		RRs := pbdm.GetResponse().GetRrs()
		for j := range RRs {
			rdata := string(RRs[j].GetRdata())
			if RRs[j].GetType() == 1 {
				addr := make(net.IP, net.IPv4len)
				copy(addr, rdata[:net.IPv4len])
				rdata = addr.String()
			}
			if RRs[j].GetType() == 28 {
				addr := make(net.IP, net.IPv6len)
				copy(addr, rdata[:net.IPv6len])
				rdata = addr.String()
			}

			rr := dnsutils.DnsAnswer{
				Name:      RRs[j].GetName(),
				Rdatatype: dnsutils.RdatatypeToString(int(RRs[j].GetType())),
				Class:     int(RRs[j].GetClass()),
				Ttl:       int(RRs[j].GetTtl()),
				Rdata:     rdata,
			}
			answers = append(answers, rr)
		}
		dm.DNS.DnsRRs.Answers = answers

		// apply all enabled transformers
		if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
			continue
		}

		// quiet text for dnstap operation ?
		if d.config.Collectors.PowerDNS.QuietText {
			if v, found := PdnsQr[dm.DnsTap.Operation]; found {
				dm.DnsTap.Operation = v
			}
			if v, found := DnsQr[dm.DNS.Type]; found {
				dm.DNS.Type = v
			}
		}

		// dispatch dns message to all generators
		for i := range sendTo {
			sendTo[i] <- dm
		}
	}

	// cleanup transformers
	subprocessors.Reset()

	// dnstap channel closed
	d.done <- true
}
