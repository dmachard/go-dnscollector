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
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

var (
	PROTOBUF_PDNS_TO_DNSTAP = map[string]string{
		"DNSQueryType":            "CLIENT_QUERY",
		"DNSResponseType":         "CLIENT_RESPONSE",
		"DNSOutgoingQueryType":    "RESOLVER_QUERY",
		"DNSIncomingResponseType": "RESOLVER_RESPONSE",
	}
)

type PdnsProcessor struct {
	connId       int
	doneRun      chan bool
	stopRun      chan bool
	doneFollow   chan bool
	stopFollow   chan bool
	recvFrom     chan []byte
	logger       *logger.Logger
	config       *dnsutils.Config
	name         string
	chanSize     int
	dropped      chan string
	droppedCount map[string]int
}

func NewPdnsProcessor(connId int, config *dnsutils.Config, logger *logger.Logger, name string, size int) PdnsProcessor {
	logger.Info("[%s] [processor=pdns] [conn=#%d] initialization...", name, connId)
	d := PdnsProcessor{
		connId:       connId,
		doneFollow:   make(chan bool),
		doneRun:      make(chan bool),
		stopFollow:   make(chan bool),
		stopRun:      make(chan bool),
		recvFrom:     make(chan []byte, size),
		chanSize:     size,
		logger:       logger,
		config:       config,
		name:         name,
		dropped:      make(chan string),
		droppedCount: map[string]int{},
	}

	d.ReadConfig()

	return d
}

func (c *PdnsProcessor) ReadConfig() {
	// nothing to read
}

func (c *PdnsProcessor) LogInfo(msg string, v ...interface{}) {
	log := fmt.Sprintf("[%s] [processor=pdns] [conn=#%d] ", c.name, c.connId)
	c.logger.Info(log+msg, v...)
}

func (c *PdnsProcessor) LogError(msg string, v ...interface{}) {
	log := fmt.Sprintf("[%s] [processor=pdns] [conn=#%d] ", c.name, c.connId)
	c.logger.Error(log+msg, v...)
}

func (d *PdnsProcessor) GetChannel() chan []byte {
	return d.recvFrom
}

func (d *PdnsProcessor) Stop() {
	d.LogInfo("stopping [goroutine=run]...")
	d.stopRun <- true
	<-d.doneRun

	d.LogInfo("stopping [goroutine=following]...")
	d.stopFollow <- true
	<-d.doneFollow
}

func (d *PdnsProcessor) Following() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
FOLLOW_LOOP:
	for {
		select {
		case <-d.stopFollow:
			close(d.dropped)
			bufferFull.Stop()
			d.doneFollow <- true
			break FOLLOW_LOOP

		case loggerName := <-d.dropped:
			if _, ok := d.droppedCount[loggerName]; !ok {
				d.droppedCount[loggerName] = 1
			} else {
				d.droppedCount[loggerName]++
			}

		case <-bufferFull.C:

			for v, k := range d.droppedCount {
				if k > 0 {
					d.LogError("logger[%s] buffer is full, %d packet(s) dropped", v, k)
					d.droppedCount[v] = 0
				}
			}
			bufferFull.Reset(watchInterval)

		}
	}
	d.LogInfo("[goroutine=follow] terminated")
}

func (d *PdnsProcessor) Run(loggersChannel []chan dnsutils.DnsMessage, loggersName []string) {
	pbdm := &powerdns_protobuf.PBDNSMessage{}

	// prepare enabled transformers
	transforms := transformers.NewTransforms(&d.config.IngoingTransformers, d.logger, d.name, loggersChannel)

	// start goroutine to count dropped messsages
	go d.Following()

	// read incoming dns message
	d.LogInfo("running... waiting dns message")
RUN_LOOP:
	for {
		select {
		case <-d.stopRun:
			transforms.Reset()
			close(d.recvFrom)
			d.doneRun <- true
			break RUN_LOOP

		case data, opened := <-d.recvFrom:
			if !opened {
				d.LogInfo("channel closed, exit")
				return
			}

			err := proto.Unmarshal(data, pbdm)
			if err != nil {
				d.LogError("pbdm decoding, %s", err)
				continue
			}

			// init dns message
			dm := dnsutils.DnsMessage{}
			dm.Init()

			// init dns message with additionnals parts
			transforms.InitDnsMessageFormat(&dm)

			// init powerdns with default values
			dm.PowerDns = &dnsutils.PowerDns{
				Tags:                  []string{},
				OriginalRequestSubnet: "",
				AppliedPolicy:         "",
				Metadata:              map[string]string{},
			}

			dm.DnsTap.Identity = string(pbdm.GetServerIdentity())
			dm.DnsTap.Operation = PROTOBUF_PDNS_TO_DNSTAP[pbdm.GetType().String()]

			if ipVersion, valid := dnsutils.IP_VERSION[pbdm.GetSocketFamily().String()]; valid {
				dm.NetworkInfo.Family = ipVersion
			} else {
				dm.NetworkInfo.Family = dnsutils.STR_UNKNOWN
			}
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
			ts := time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))
			dm.DnsTap.Timestamp = ts.UnixNano()
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

			// get PowerDNS metadata
			metas := make(map[string]string)
			for _, e := range pbdm.GetMeta() {
				metas[e.GetKey()] = strings.Join(e.Value.StringVal, " ")
			}
			pdns.Metadata = metas

			// finally set pdns to dns message
			dm.PowerDns = &pdns

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

			// prepare a fake DNS payload
			dns.Id = func() uint16 { return uint16(pbdm.GetId()) }
			fakePkt := new(dns.Msg)
			fakePkt.SetQuestion(pbdm.Question.GetQName(), uint16(pbdm.Question.GetQType()))

			// add reply
			if int(pbdm.Type.Number())%2 != 1 {
				// is a reply
				fakePkt.Response = true

				// set reply code
				fakePkt.Rcode = int(pbdm.Response.GetRcode())

				// add RR only A, AAAA and CNAME are exported by PowerDNS
				rrs := pbdm.GetResponse().GetRrs()
				for j := range rrs {
					// prepare header
					RR_Header := dns.RR_Header{
						Name:     rrs[j].GetName(),
						Rrtype:   uint16(rrs[j].GetType()),
						Class:    uint16(rrs[j].GetClass()),
						Ttl:      rrs[j].GetTtl(),
						Rdlength: uint16(len(rrs[j].GetRdata())),
					}
					// init rr if valid
					newFn, ok := dns.TypeToRR[RR_Header.Rrtype]
					if !ok {
						continue
					}
					RR := newFn()
					*RR.Header() = RR_Header

					switch {
					// A or AAAA
					case RRs[j].GetType() == 1 || RRs[j].GetType() == 28:
						RR, _, err := dns.UnpackRRWithHeader(RR_Header, rrs[j].GetRdata(), 0)
						if err == nil {
							fakePkt.Answer = append(fakePkt.Answer, RR)
						}
					// CNAME
					case RRs[j].GetType() == 5:
						RR_Target := make([]byte, 255)
						off, err := dns.PackDomainName(string(rrs[j].GetRdata()), RR_Target, 0, map[string]int{}, false)
						if err != nil {
							continue
						}
						RR_Target = RR_Target[:off]
						RR_Header.Header().Rdlength = uint16(len(RR_Target))
						RR, _, err := dns.UnpackRRWithHeader(RR_Header, RR_Target, 0)
						if err == nil {
							fakePkt.Answer = append(fakePkt.Answer, RR)
						}
					}
				}
			}
			wirePkt, err := fakePkt.Pack()
			if err != nil {
				d.LogError("dns encoding failed, %s", err)
				continue
			}
			dm.DNS.Payload = wirePkt

			// apply all enabled transformers
			if transforms.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// dispatch dns messages to connected loggers
			for i := range loggersChannel {
				select {
				case loggersChannel[i] <- dm: // Successful send to logger channel
				default:
					d.dropped <- loggersName[i]
				}
			}
		}
	}
	d.LogInfo("[goroutine=run] terminated")
}
