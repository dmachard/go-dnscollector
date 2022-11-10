package collectors

import (
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-logger"
	"golang.org/x/net/publicsuffix"
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
	name     string
}

func NewDnstapProcessor(config *dnsutils.Config, logger *logger.Logger, name string) DnstapProcessor {
	logger.Info("[%s] dnstap processor - initialization...", name)
	d := DnstapProcessor{
		done:     make(chan bool),
		recvFrom: make(chan []byte, 512),
		logger:   logger,
		config:   config,
		name:     name,
	}

	d.ReadConfig()

	return d
}

func (d *DnstapProcessor) ReadConfig() {
	// todo - checking settings
}

func (c *DnstapProcessor) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] dnstap processor - "+msg, v...)
}

func (c *DnstapProcessor) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] dnstap processor - "+msg, v...)
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
	cache_ttl := dnsutils.NewDnsCache(time.Duration(d.config.Collectors.Dnstap.QueryTimeout) * time.Second)
	d.LogInfo("dns cached enabled: %t", d.config.Collectors.Dnstap.CacheSupport)

	// prepare enabled transformers
	subprocessors := transformers.NewTransforms(d.config, d.logger, d.name)

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
			dm.DnsTap.Identity = string(identity)
		}

		dm.DnsTap.Operation = dt.GetMessage().GetType().String()
		dm.NetworkInfo.Family = dt.GetMessage().GetSocketFamily().String()
		dm.NetworkInfo.Protocol = dt.GetMessage().GetSocketProtocol().String()

		// decode query address and port
		queryip := dt.GetMessage().GetQueryAddress()
		if len(queryip) > 0 {
			dm.NetworkInfo.QueryIp = net.IP(queryip).String()
		}
		queryport := dt.GetMessage().GetQueryPort()
		if queryport > 0 {
			dm.NetworkInfo.QueryPort = strconv.FormatUint(uint64(queryport), 10)
		}

		// decode response address and port
		responseip := dt.GetMessage().GetResponseAddress()
		if len(responseip) > 0 {
			dm.NetworkInfo.ResponseIp = net.IP(responseip).String()
		}
		responseport := dt.GetMessage().GetResponsePort()
		if responseport > 0 {
			dm.NetworkInfo.ResponsePort = strconv.FormatUint(uint64(responseport), 10)
		}

		// get dns payload and timestamp according to the type (query or response)
		op := dnstap.Message_Type_value[dm.DnsTap.Operation]
		if op%2 == 1 {
			dns_payload := dt.GetMessage().GetQueryMessage()
			dm.DNS.Payload = dns_payload
			dm.DNS.Length = len(dns_payload)
			dm.DNS.Type = dnsutils.DnsQuery
			dm.DnsTap.TimeSec = int(dt.GetMessage().GetQueryTimeSec())
			dm.DnsTap.TimeNsec = int(dt.GetMessage().GetQueryTimeNsec())
		} else {
			dns_payload := dt.GetMessage().GetResponseMessage()
			dm.DNS.Payload = dns_payload
			dm.DNS.Length = len(dns_payload)
			dm.DNS.Type = dnsutils.DnsReply
			dm.DnsTap.TimeSec = int(dt.GetMessage().GetResponseTimeSec())
			dm.DnsTap.TimeNsec = int(dt.GetMessage().GetResponseTimeNsec())
		}

		// compute timestamp
		dm.DnsTap.Timestamp = float64(dm.DnsTap.TimeSec) + float64(dm.DnsTap.TimeNsec)/1e9
		ts := time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))
		dm.DnsTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

		// decode the dns payload to get id, rcode and the number of question
		// number of answer, ignore invalid packet
		dnsHeader, err := dnsutils.DecodeDns(dm.DNS.Payload)
		if err != nil {
			// parser error
			dm.DNS.MalformedPacket = true
			d.LogInfo("dns parser malformed packet: %s", err)
		}

		if err = dnsutils.DecodePayload(&dm, &dnsHeader, d.config); err != nil {
			// decoding error
			if d.config.Global.Trace.LogMalformed {
				d.LogError("%v - %v", err, dm)
				d.LogError("dump invalid dns payload: %v", dm.DNS.Payload)
			}
		}

		// compute latency if possible
		if d.config.Collectors.Dnstap.CacheSupport {
			if len(dm.NetworkInfo.QueryIp) > 0 && queryport > 0 && !dm.DNS.MalformedPacket {
				// compute the hash of the query
				hash_data := []string{dm.NetworkInfo.QueryIp, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.Id)}

				hashfnv := fnv.New64a()
				hashfnv.Write([]byte(strings.Join(hash_data[:], "+")))

				if dm.DNS.Type == dnsutils.DnsQuery {
					cache_ttl.Set(hashfnv.Sum64(), dm.DnsTap.Timestamp)
				} else {
					value, ok := cache_ttl.Get(hashfnv.Sum64())
					if ok {
						dm.DnsTap.Latency = dm.DnsTap.Timestamp - value
					}
				}
			}
		}

		// convert latency to human
		dm.DnsTap.LatencySec = fmt.Sprintf("%.6f", dm.DnsTap.Latency)

		// Public suffix
		ps, _ := publicsuffix.PublicSuffix(dm.DNS.Qname)
		dm.DNS.QnamePublicSuffix = ps
		if etpo, err := publicsuffix.EffectiveTLDPlusOne(dm.DNS.Qname); err == nil {
			dm.DNS.QnameEffectiveTLDPlusOne = etpo
		}

		// apply all enabled transformers
		if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
			continue
		}

		// quiet text for dnstap operation ?
		if d.config.Collectors.Dnstap.QuietText {
			if v, found := DnstapMessage[dm.DnsTap.Operation]; found {
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
