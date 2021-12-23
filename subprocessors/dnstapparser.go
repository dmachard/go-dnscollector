package subprocessors

import (
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

var (
	DnstapMessage = map[string]string{
		"AUTH_QUERY":         "AQ",
		"AUTH_RESPONSE":      "AR",
		"RESOLVER_QUERY":     "RQ",
		"RESOLVER_RESPONSE":  "RR",
		"CLIENT_QUERY":       "CQ",
		"CLIENT_RESPONSE":    "CR",
		"FORWARDER_QUERY":    "FQ",
		"FORWARDER_RESPONSE": "FR",
		"STUB_QUERY":         "SQ",
		"STUB_RESPONSE":      "SR",
		"TOOL_QUERY":         "TQ",
		"TOOL_RESPONSE":      "TR",
		"UPDATE_QUERY":       "UQ",
		"UPDATE_RESPONSE":    "UR",
	}
	DnsQr = map[string]string{
		"QUERY": "Q",
		"REPLY": "R",
	}
)

func GetFakeDnstap(dnsquery []byte) *dnstap.Dnstap {
	dt_query := &dnstap.Dnstap{}

	dt := dnstap.Dnstap_MESSAGE
	dt_query.Identity = []byte("dnstap-generator")
	dt_query.Version = []byte("-")
	dt_query.Type = &dt

	mt := dnstap.Message_CLIENT_QUERY
	sf := dnstap.SocketFamily_INET
	sp := dnstap.SocketProtocol_UDP

	now := time.Now()
	tsec := uint64(now.Unix())
	tnsec := uint32(uint64(now.UnixNano()) - uint64(now.Unix())*1e9)

	rport := uint32(53)
	qport := uint32(5300)

	msg := &dnstap.Message{Type: &mt}
	msg.SocketFamily = &sf
	msg.SocketProtocol = &sp
	msg.QueryAddress = net.ParseIP("127.0.0.1")
	msg.QueryPort = &qport
	msg.ResponseAddress = net.ParseIP("127.0.0.2")
	msg.ResponsePort = &rport

	msg.QueryMessage = dnsquery
	msg.QueryTimeSec = &tsec
	msg.QueryTimeNsec = &tnsec

	dt_query.Message = msg
	return dt_query
}

type DnstapProcessor struct {
	done     chan bool
	recvFrom chan []byte
	logger   *logger.Logger
	config   *dnsutils.Config
}

func NewDnstapProcessor(config *dnsutils.Config, logger *logger.Logger) DnstapProcessor {
	logger.Info("dnstap processor - initialization...")
	d := DnstapProcessor{
		done:     make(chan bool),
		recvFrom: make(chan []byte, 512),
		logger:   logger,
		config:   config,
	}

	d.ReadConfig()

	return d
}

func (d *DnstapProcessor) ReadConfig() {
	// todo - checking settings
}

func (c *DnstapProcessor) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("processor dnstap parser - "+msg, v...)
}

func (c *DnstapProcessor) LogError(msg string, v ...interface{}) {
	c.logger.Error("procesor dnstap parser - "+msg, v...)
}

func (d *DnstapProcessor) GetChannel() chan []byte {
	return d.recvFrom
}

func (d *DnstapProcessor) Stop() {
	close(d.recvFrom)

	// read done channel and block until run is terminated
	<-d.done
	close(d.done)
}

func (d *DnstapProcessor) Run(sendTo []chan dnsutils.DnsMessage) {
	dt := &dnstap.Dnstap{}

	// dns cache to compute latency between response and query
	cache_ttl := NewCacheDnsProcessor(time.Duration(d.config.Subprocessors.Cache.QueryTimeout) * time.Second)

	// geoip
	geoip := NewDnsGeoIpProcessor(d.config, d.logger)
	if err := geoip.Open(); err != nil {
		d.LogError("geoip init failed: %v+", err)
	}
	if geoip.IsEnabled() {
		d.LogInfo("geoip is enabled")
	}
	defer geoip.Close()

	// filtering
	filtering := NewFilteringProcessor(d.config, d.logger)

	// user privacy
	ipPrivacy := NewIpAnonymizerSubprocessor(d.config)
	qnamePrivacy := NewQnameReducerSubprocessor(d.config)

	// read incoming dns message
	d.LogInfo("running... waiting incoming dns message")
	for data := range d.recvFrom {

		err := proto.Unmarshal(data, dt)
		if err != nil {
			continue
		}

		dm := dnsutils.DnsMessage{}
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
			dm.Type = dnsutils.DnsQuery
			dm.TimeSec = int(dt.GetMessage().GetQueryTimeSec())
			dm.TimeNsec = int(dt.GetMessage().GetQueryTimeNsec())
		} else {
			dns_payload := dt.GetMessage().GetResponseMessage()
			dm.Payload = dns_payload
			dm.Length = len(dns_payload)
			dm.Type = dnsutils.DnsReply
			dm.TimeSec = int(dt.GetMessage().GetResponseTimeSec())
			dm.TimeNsec = int(dt.GetMessage().GetResponseTimeNsec())
		}

		// compute timestamp
		dm.Timestamp = float64(dm.TimeSec) + float64(dm.TimeNsec)/1e9
		ts := time.Unix(int64(dm.TimeSec), int64(dm.TimeNsec))
		dm.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

		// decode the dns payload to get id, rcode and the number of question
		// number of answer, ignore invalid packet
		dnsHeader, err := DecodeDns(dm.Payload)
		if err != nil {
			// parser error
			dm.MalformedPacket = 1
			d.LogInfo("dns parser malformed packet: %s", err)
			//continue
		}

		dm.Id = dnsHeader.id
		dm.Rcode = RcodeToString(dnsHeader.rcode)
		if dnsHeader.tc == 1 {
			dm.Truncated = "TC"
		}
		if dnsHeader.aa == 1 {
			dm.AuthoritativeAnswer = "AA"
		}
		if dnsHeader.ra == 1 {
			dm.RecursionAvailable = "RA"
		}
		if dnsHeader.ad == 1 {
			dm.AuthenticData = "AD"
		}

		// continue to decode the dns payload to extract the qname and rrtype
		var dns_offsetrr int
		if dnsHeader.qdcount > 0 && dm.MalformedPacket == 0 {
			dns_qname, dns_rrtype, offsetrr, err := DecodeQuestion(dm.Payload)
			if err != nil {
				dm.MalformedPacket = 1
				d.LogInfo("dns parser malformed question: %s", err)
				//continue
			}
			if d.config.Subprocessors.QnameLowerCase {
				dm.Qname = strings.ToLower(dns_qname)
			} else {
				dm.Qname = dns_qname
			}
			dm.Qtype = RdatatypeToString(dns_rrtype)
			dns_offsetrr = offsetrr
		}

		//  decode answers except if the packet is malformed
		if dnsHeader.ancount > 0 && dm.MalformedPacket == 0 {
			var offsetrr int
			dm.Answers, offsetrr, err = DecodeAnswer(dnsHeader.ancount, dns_offsetrr, dm.Payload)
			if err != nil {
				dm.MalformedPacket = 1
				d.LogInfo("dns parser malformed answers: %s", err)
			}
			dns_offsetrr = offsetrr
		}

		//  decode authoritative answers except if the packet is malformed
		if dnsHeader.nscount > 0 && dm.MalformedPacket == 0 {
			var offsetrr int
			dm.Nameservers, offsetrr, err = DecodeAnswer(dnsHeader.nscount, dns_offsetrr, dm.Payload)
			if err != nil {
				dm.MalformedPacket = 1
				d.LogInfo("dns parser malformed nameservers answers: %s", err)
			}
			dns_offsetrr = offsetrr
		}

		//  decode additional answers ?
		if dnsHeader.arcount > 0 && dm.MalformedPacket == 0 {
			// decode answers
			dm.AdditionalAnswers, _, err = DecodeAnswer(dnsHeader.arcount, dns_offsetrr, dm.Payload)
			if err != nil {
				dm.MalformedPacket = 1
				d.LogInfo("dns parser malformed additional answers: %s", err)
			}
		}

		// compute latency if possible
		if d.config.Subprocessors.Cache.Enable {
			if len(dm.QueryIp) > 0 && queryport > 0 && dm.MalformedPacket == 0 {
				// compute the hash of the query
				hash_data := []string{dm.QueryIp, dm.QueryPort, strconv.Itoa(dm.Id)}

				hashfnv := fnv.New64a()
				hashfnv.Write([]byte(strings.Join(hash_data[:], "+")))

				if dm.Type == dnsutils.DnsQuery {
					cache_ttl.Set(hashfnv.Sum64(), dm.Timestamp)
				} else {
					value, ok := cache_ttl.Get(hashfnv.Sum64())
					if ok {
						dm.Latency = dm.Timestamp - value
					}
				}
			}
		}

		// convert latency to human
		dm.LatencySec = fmt.Sprintf("%.6f", dm.Latency)

		// qname privacy
		if qnamePrivacy.IsEnabled() {
			dm.Qname = qnamePrivacy.Minimaze(dm.Qname)
		}

		// filtering
		if filtering.CheckIfDrop(&dm) {
			continue
		}

		// geoip feature
		if geoip.IsEnabled() {
			geoInfo, err := geoip.Lookup(dm.QueryIp)
			if err != nil {
				d.LogError("geoip loopkup failed: %v+", err)
			}
			dm.Continent = geoInfo.Continent
			dm.CountryIsoCode = geoInfo.CountryISOCode
			dm.City = geoInfo.City
			dm.AutonomousSystemNumber = geoInfo.ASN
			dm.AutonomousSystemOrg = geoInfo.ASO
		}

		// ip anonymisation ?
		if ipPrivacy.IsEnabled() {
			dm.QueryIp = ipPrivacy.Anonymize(dm.QueryIp)
		}

		// quiet text for dnstap operation ?
		if d.config.Subprocessors.QuietText.Dnstap {
			if v, found := DnstapMessage[dm.Operation]; found {
				dm.Operation = v
			}
		}
		if d.config.Subprocessors.QuietText.Dns {
			if v, found := DnsQr[dm.Type]; found {
				dm.Type = v
			}
		}

		// dispatch dns message to all generators
		for i := range sendTo {
			sendTo[i] <- dm
		}
	}

	// dnstap channel closed
	d.done <- true
}
