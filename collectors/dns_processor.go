package collectors

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

func GetFakeDns() ([]byte, error) {
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dns.collector.", dns.TypeA)
	return dnsmsg.Pack()
}

type DnsProcessor struct {
	done         chan bool
	recvFrom     chan dnsutils.DnsMessage
	logger       *logger.Logger
	config       *dnsutils.Config
	cacheSupport bool
	queryTimeout int
	name         string
}

func NewDnsProcessor(config *dnsutils.Config, logger *logger.Logger, name string) DnsProcessor {
	logger.Info("[%s] processor dns - initialization...", name)
	d := DnsProcessor{
		done:     make(chan bool),
		recvFrom: make(chan dnsutils.DnsMessage, 512),
		logger:   logger,
		config:   config,
		name:     name,
	}

	d.ReadConfig()

	return d
}

func (d *DnsProcessor) ReadConfig() {
	d.cacheSupport = false
	d.queryTimeout = 5
}

func (c *DnsProcessor) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] dns processor - "+msg, v...)
}

func (c *DnsProcessor) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] dns processor - "+msg, v...)
}

func (d *DnsProcessor) GetChannel() chan dnsutils.DnsMessage {
	return d.recvFrom
}

func (d *DnsProcessor) GetChannelList() []chan dnsutils.DnsMessage {
	channel := []chan dnsutils.DnsMessage{}
	channel = append(channel, d.recvFrom)
	return channel
}

func (d *DnsProcessor) Stop() {
	close(d.recvFrom)

	// read done channel and block until run is terminated
	<-d.done
	close(d.done)
}

func (d *DnsProcessor) Run(sendTo []chan dnsutils.DnsMessage) {

	// dns cache to compute latency between response and query
	cache_ttl := dnsutils.NewDnsCache(time.Duration(d.queryTimeout) * time.Second)
	d.LogInfo("dns cached enabled: %t", d.cacheSupport)

	// prepare enabled transformers
	subprocessors := transformers.NewTransforms(&d.config.IngoingTransformers, d.logger, d.name)

	// read incoming dns message
	d.LogInfo("running... waiting incoming dns message")
	for dm := range d.recvFrom {
		// compute timestamp
		dm.DnsTap.Timestamp = float64(dm.DnsTap.TimeSec) + float64(dm.DnsTap.TimeNsec)/1e9
		ts := time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))
		dm.DnsTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

		// decode the dns payload
		dnsHeader, err := dnsutils.DecodeDns(dm.DNS.Payload)
		if err != nil {
			dm.DNS.MalformedPacket = true
			d.LogError("dns parser malformed packet: %s - %v+", err, dm)
		}

		// dns reply ?
		if dnsHeader.Qr == 1 {
			dm.DnsTap.Operation = "CLIENT_RESPONSE"
			dm.DNS.Type = dnsutils.DnsReply
			qip := dm.NetworkInfo.QueryIp
			qport := dm.NetworkInfo.QueryPort
			dm.NetworkInfo.QueryIp = dm.NetworkInfo.ResponseIp
			dm.NetworkInfo.QueryPort = dm.NetworkInfo.ResponsePort
			dm.NetworkInfo.ResponseIp = qip
			dm.NetworkInfo.ResponsePort = qport
		} else {
			dm.DNS.Type = dnsutils.DnsQuery
			dm.DnsTap.Operation = dnsutils.DNSTAP_CLIENT_QUERY
		}

		if err = dnsutils.DecodePayload(&dm, &dnsHeader, d.config); err != nil {
			d.LogError("%v - %v", err, dm)
		}

		if dm.DNS.MalformedPacket {
			if d.config.Global.Trace.LogMalformed {
				d.LogInfo("payload: %v", dm.DNS.Payload)
			}
		}

		// compute latency if possible
		if d.config.Collectors.LiveCapture.CacheSupport {
			queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
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

		// dispatch dns message to all generators
		for i := range sendTo {
			sendTo[i] <- dm
		}
	}

	// cleanup transformers
	subprocessors.Reset()

	// dnstap channel consumer closed
	d.done <- true
}
