package processors

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
	ProtobufPowerDNSToDNSTap = map[string]string{
		"DNSQueryType":            "CLIENT_QUERY",
		"DNSResponseType":         "CLIENT_RESPONSE",
		"DNSOutgoingQueryType":    "RESOLVER_QUERY",
		"DNSIncomingResponseType": "RESOLVER_RESPONSE",
	}
)

type PdnsProcessor struct {
	ConnID       int
	doneRun      chan bool
	stopRun      chan bool
	doneMonitor  chan bool
	stopMonitor  chan bool
	recvFrom     chan []byte
	logger       *logger.Logger
	config       *dnsutils.Config
	ConfigChan   chan *dnsutils.Config
	name         string
	chanSize     int
	dropped      chan string
	droppedCount map[string]int
}

func NewPdnsProcessor(connID int, config *dnsutils.Config, logger *logger.Logger, name string, size int) PdnsProcessor {
	logger.Info("[%s] processor=pdns#%d - initialization...", name, connID)
	d := PdnsProcessor{
		ConnID:       connID,
		doneMonitor:  make(chan bool),
		doneRun:      make(chan bool),
		stopMonitor:  make(chan bool),
		stopRun:      make(chan bool),
		recvFrom:     make(chan []byte, size),
		chanSize:     size,
		logger:       logger,
		config:       config,
		ConfigChan:   make(chan *dnsutils.Config),
		name:         name,
		dropped:      make(chan string),
		droppedCount: map[string]int{},
	}
	return d
}

func (p *PdnsProcessor) LogInfo(msg string, v ...interface{}) {
	var log string
	if p.ConnID == 0 {
		log = fmt.Sprintf("[%s] processor=powerdns - ", p.name)
	} else {
		log = fmt.Sprintf("[%s] processor=powerdns#%d - ", p.name, p.ConnID)
	}
	p.logger.Info(log+msg, v...)
}

func (p *PdnsProcessor) LogError(msg string, v ...interface{}) {
	var log string
	if p.ConnID == 0 {
		log = fmt.Sprintf("[%s] processor=powerdns - ", p.name)
	} else {
		log = fmt.Sprintf("[%s] processor=powerdns#%d - ", p.name, p.ConnID)
	}
	p.logger.Error(log+msg, v...)
}

func (p *PdnsProcessor) GetChannel() chan []byte {
	return p.recvFrom
}

func (p *PdnsProcessor) Stop() {
	p.LogInfo("stopping to process...")
	p.stopRun <- true
	<-p.doneRun

	p.LogInfo("stopping to monitor loggers...")
	p.stopMonitor <- true
	<-p.doneMonitor
}

func (p *PdnsProcessor) MonitorLoggers() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
FOLLOW_LOOP:
	for {
		select {
		case <-p.stopMonitor:
			close(p.dropped)
			bufferFull.Stop()
			p.doneMonitor <- true
			break FOLLOW_LOOP

		case loggerName := <-p.dropped:
			if _, ok := p.droppedCount[loggerName]; !ok {
				p.droppedCount[loggerName] = 1
			} else {
				p.droppedCount[loggerName]++
			}

		case <-bufferFull.C:

			for v, k := range p.droppedCount {
				if k > 0 {
					p.LogError("logger[%s] buffer is full, %d packet(s) dropped", v, k)
					p.droppedCount[v] = 0
				}
			}
			bufferFull.Reset(watchInterval)

		}
	}
	p.LogInfo("monitor terminated")
}

func (p *PdnsProcessor) Run(loggersChannel []chan dnsutils.DNSMessage, loggersName []string) {
	pbdm := &powerdns_protobuf.PBDNSMessage{}

	// prepare enabled transformers
	transforms := transformers.NewTransforms(&p.config.IngoingTransformers, p.logger, p.name, loggersChannel, p.ConnID)

	// start goroutine to count dropped messsages
	go p.MonitorLoggers()

	// read incoming dns message
	p.LogInfo("waiting dns message to process...")
RUN_LOOP:
	for {
		select {
		case cfg := <-p.ConfigChan:
			p.config = cfg
			transforms.ReloadConfig(&cfg.IngoingTransformers)

		case <-p.stopRun:
			transforms.Reset()
			p.doneRun <- true
			break RUN_LOOP

		case data, opened := <-p.recvFrom:
			if !opened {
				p.LogInfo("channel closed, exit")
				return
			}

			err := proto.Unmarshal(data, pbdm)
			if err != nil {
				p.LogError("pbdm decoding, %s", err)
				continue
			}

			// init dns message
			dm := dnsutils.DNSMessage{}
			dm.Init()

			// init dns message with additionnals parts
			transforms.InitDNSMessageFormat(&dm)

			// init powerdns with default values
			dm.PowerDNS = &dnsutils.PowerDNS{
				Tags:                  []string{},
				OriginalRequestSubnet: "",
				AppliedPolicy:         "",
				Metadata:              map[string]string{},
			}

			dm.DNSTap.Identity = string(pbdm.GetServerIdentity())
			dm.DNSTap.Operation = ProtobufPowerDNSToDNSTap[pbdm.GetType().String()]

			if ipVersion, valid := dnsutils.IPVersion[pbdm.GetSocketFamily().String()]; valid {
				dm.NetworkInfo.Family = ipVersion
			} else {
				dm.NetworkInfo.Family = dnsutils.StrUnknown
			}
			dm.NetworkInfo.Protocol = pbdm.GetSocketProtocol().String()

			if pbdm.From != nil {
				dm.NetworkInfo.QueryIP = net.IP(pbdm.From).String()
			}
			dm.NetworkInfo.QueryPort = strconv.FormatUint(uint64(pbdm.GetFromPort()), 10)
			dm.NetworkInfo.ResponseIP = net.IP(pbdm.To).String()
			dm.NetworkInfo.ResponsePort = strconv.FormatUint(uint64(pbdm.GetToPort()), 10)

			dm.DNS.ID = int(pbdm.GetId())
			dm.DNS.Length = int(pbdm.GetInBytes())
			dm.DNSTap.TimeSec = int(pbdm.GetTimeSec())
			dm.DNSTap.TimeNsec = int(pbdm.GetTimeUsec()) * 1e3

			if int(pbdm.Type.Number())%2 == 1 {
				dm.DNS.Type = dnsutils.DNSQuery
			} else {
				dm.DNS.Type = dnsutils.DNSReply

				tsQuery := float64(pbdm.Response.GetQueryTimeSec()) + float64(pbdm.Response.GetQueryTimeUsec())/1e6
				tsReply := float64(pbdm.GetTimeSec()) + float64(pbdm.GetTimeUsec())/1e6

				// convert latency to human
				dm.DNSTap.Latency = tsReply - tsQuery
				dm.DNSTap.LatencySec = fmt.Sprintf("%.6f", dm.DNSTap.Latency)
				dm.DNS.Rcode = dnsutils.RcodeToString(int(pbdm.Response.GetRcode()))
			}

			// compute timestamp
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			dm.DNSTap.Timestamp = ts.UnixNano()
			dm.DNSTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

			dm.DNS.Qname = pbdm.Question.GetQName()
			// remove ending dot ?
			dm.DNS.Qname = strings.TrimSuffix(dm.DNS.Qname, ".")

			// get query type
			dm.DNS.Qtype = dnsutils.RdatatypeToString(int(pbdm.Question.GetQType()))

			// get specific powerdns params
			pdns := dnsutils.PowerDNS{}

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
			dm.PowerDNS = &pdns

			// decode answers
			answers := []dnsutils.DNSAnswer{}
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

				rr := dnsutils.DNSAnswer{
					Name:      RRs[j].GetName(),
					Rdatatype: dnsutils.RdatatypeToString(int(RRs[j].GetType())),
					Class:     int(RRs[j].GetClass()),
					TTL:       int(RRs[j].GetTtl()),
					Rdata:     rdata,
				}
				answers = append(answers, rr)
			}
			dm.DNS.DNSRRs.Answers = answers

			if p.config.Collectors.PowerDNS.AddDNSPayload {

				qname := dns.Fqdn(pbdm.Question.GetQName())
				newDNS := new(dns.Msg)
				newDNS.Id = uint16(pbdm.GetId())
				newDNS.Response = false

				question := dns.Question{
					Name:   qname,
					Qtype:  uint16(pbdm.Question.GetQType()),
					Qclass: uint16(pbdm.Question.GetQClass()),
				}
				newDNS.Question = append(newDNS.Question, question)

				if int(pbdm.Type.Number())%2 != 1 {
					newDNS.Response = true
					newDNS.Rcode = int(pbdm.Response.GetRcode())

					newDNS.Answer = []dns.RR{}
					rrs := pbdm.GetResponse().GetRrs()
					for j := range rrs {
						rrname := dns.Fqdn(rrs[j].GetName())
						switch rrs[j].GetType() {
						// A
						case 1:
							rdata := &dns.A{
								Hdr: dns.RR_Header{Name: rrname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								A:   net.IP(rrs[j].GetRdata()),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						// AAAA
						case 28:
							rdata := &dns.AAAA{
								Hdr:  dns.RR_Header{Name: rrname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								AAAA: net.IP(rrs[j].GetRdata()),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						// CNAME
						case 5:
							rdata := &dns.CNAME{
								Hdr:    dns.RR_Header{Name: rrname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								Target: dns.Fqdn(string(rrs[j].GetRdata())),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						}

					}

				}

				pktWire, err := newDNS.Pack()
				if err == nil {
					dm.DNS.Payload = pktWire
					if dm.DNS.Length == 0 {
						dm.DNS.Length = len(pktWire)
					}
				} else {
					dm.DNS.MalformedPacket = true
				}
			}

			// apply all enabled transformers
			if transforms.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// dispatch dns messages to connected loggers
			for i := range loggersChannel {
				select {
				case loggersChannel[i] <- dm: // Successful send to logger channel
				default:
					p.dropped <- loggersName[i]
				}
			}
		}
	}
	p.LogInfo("processing terminated")
}
