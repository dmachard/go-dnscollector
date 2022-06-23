package collectors

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/subprocessors"
	"github.com/dmachard/go-logger"
	"github.com/miekg/dns"
)

func GetFakeDns() ([]byte, error) {
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dns.collector.", dns.TypeA)
	return dnsmsg.Pack()
}

type DnsProcessor struct {
	done     chan bool
	recvFrom chan dnsutils.DnsMessage
	logger   *logger.Logger
	config   *dnsutils.Config
	name     string
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
	// todo - checking settings
}

func (c *DnsProcessor) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] processor dns - "+msg, v...)
}

func (c *DnsProcessor) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] procesor dns - "+msg, v...)
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
	cache_ttl := dnsutils.NewDnsCache(time.Duration(d.config.Subprocessors.Cache.QueryTimeout) * time.Second)

	// geoip
	geoip := subprocessors.NewDnsGeoIpProcessor(d.config, d.logger)
	if err := geoip.Open(); err != nil {
		d.LogError("geoip init failed: %v+", err)
	}
	if geoip.IsEnabled() {
		d.LogInfo("geoip is enabled")
	}
	defer geoip.Close()

	// filtering
	filtering := subprocessors.NewFilteringProcessor(d.config, d.logger, d.name)

	// user privacy
	ipPrivacy := subprocessors.NewIpAnonymizerSubprocessor(d.config)
	qnamePrivacy := subprocessors.NewQnameReducerSubprocessor(d.config)

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
			dm.DNS.MalformedPacket = 1
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
			dm.DnsTap.Operation = "CLIENT_QUERY"
		}

		if err = dnsutils.DecodePayload(&dm, &dnsHeader, d.config); err != nil {
			d.LogError("%v - %v", err, dm)
		}

		if dm.DNS.MalformedPacket == 1 {
			if d.config.Trace.LogMalformed {
				d.LogInfo("payload: %v", dm.DNS.Payload)
			}
		}

		// compute latency if possible
		if d.config.Subprocessors.Cache.Enable {
			queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
			if len(dm.NetworkInfo.QueryIp) > 0 && queryport > 0 && dm.DNS.MalformedPacket == 0 {
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

		// qname privacy
		if qnamePrivacy.IsEnabled() {
			dm.DNS.Qname = qnamePrivacy.Minimaze(dm.DNS.Qname)
		}

		// filtering
		if filtering.CheckIfDrop(&dm) {
			continue
		}

		// geoip feature ?
		if geoip.IsEnabled() {
			geoInfo, err := geoip.Lookup(dm.NetworkInfo.QueryIp)
			if err != nil {
				d.LogError("geoip loopkup failed: %v+", err)
			}
			dm.Geo.Continent = geoInfo.Continent
			dm.Geo.CountryIsoCode = geoInfo.CountryISOCode
			dm.Geo.City = geoInfo.City
			dm.NetworkInfo.AutonomousSystemNumber = geoInfo.ASN
			dm.NetworkInfo.AutonomousSystemOrg = geoInfo.ASO
		}

		// ip anonymisation ?
		if ipPrivacy.IsEnabled() {
			dm.NetworkInfo.QueryIp = ipPrivacy.Anonymize(dm.NetworkInfo.QueryIp)
		}

		// dispatch dns message to all generators
		for i := range sendTo {
			sendTo[i] <- dm
		}
	}

	// dnstap channel consumer closed
	d.done <- true
}
