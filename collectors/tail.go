package collectors

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/subprocessors"
	"github.com/dmachard/go-logger"
	"github.com/hpcloud/tail"
	"github.com/miekg/dns"
)

type Tail struct {
	done    chan bool
	tailf   *tail.Tail
	loggers []dnsutils.Worker
	config  *dnsutils.Config
	logger  *logger.Logger
}

func NewTail(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger) *Tail {
	s := &Tail{
		done:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
	}
	s.ReadConfig()
	return s
}

func (c *Tail) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *Tail) ReadConfig() {
	//tbc
}

func (o *Tail) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("collector tail - "+msg, v...)
}

func (o *Tail) LogError(msg string, v ...interface{}) {
	o.logger.Error("collector tail - "+msg, v...)
}

func (c *Tail) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *Tail) Stop() {
	c.LogInfo("stopping...")

	// Stop to follow file
	c.LogInfo("stop following file...")
	c.tailf.Stop()

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *Tail) Follow() error {
	var err error
	location := tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}
	config := tail.Config{Location: &location, ReOpen: true, Follow: true, Logger: tail.DiscardingLogger, Poll: true, MustExist: true}
	c.tailf, err = tail.TailFile(c.config.Collectors.Tail.FilePath, config)
	if err != nil {
		return err
	}
	return nil
}

func (c *Tail) Run() {
	c.LogInfo("starting collector...")
	err := c.Follow()
	if err != nil {
		c.logger.Fatal("collector tailf - unable to follow file: ", err)
	}

	// geoip
	geoip := subprocessors.NewDnsGeoIpProcessor(c.config)
	if err := geoip.Open(); err != nil {
		c.LogError("geoip init failed: %v+", err)
	}
	if geoip.IsEnabled() {
		c.LogInfo("geoip is enabled")
	}
	defer geoip.Close()

	// filtering
	filtering := subprocessors.NewFilteringProcessor(c.config)

	// ip anonymizer
	anonIp := subprocessors.NewIpAnonymizerSubprocessor(c.config)

	dm := dnsutils.DnsMessage{}
	dm.Init()
	dm.Identity = c.config.Subprocessors.ServerId

	for line := range c.tailf.Lines {
		var matches []string
		var re *regexp.Regexp

		if len(c.config.Collectors.Tail.PatternQuery) > 0 {
			re = regexp.MustCompile(c.config.Collectors.Tail.PatternQuery)
			matches = re.FindStringSubmatch(line.Text)
			dm.Type = "query"
			dm.Operation = "QUERY"
		}

		if len(c.config.Collectors.Tail.PatternReply) > 0 && len(matches) == 0 {
			re = regexp.MustCompile(c.config.Collectors.Tail.PatternReply)
			matches = re.FindStringSubmatch(line.Text)
			dm.Type = "reply"
			dm.Operation = "REPLY"
		}

		if len(matches) == 0 {
			continue
		}

		qrIndex := re.SubexpIndex("qr")
		if qrIndex != -1 {
			dm.Operation = matches[qrIndex]
		}

		var t time.Time
		timestampIndex := re.SubexpIndex("timestamp")
		if timestampIndex != -1 {
			t, err = time.Parse(c.config.Collectors.Tail.TimeLayout, matches[timestampIndex])
			if err != nil {
				continue
			}
		} else {
			t = time.Now()
		}
		dm.TimeSec = int(t.Unix())
		dm.TimeNsec = int(t.UnixNano() - t.Unix()*1e9)

		identityIndex := re.SubexpIndex("identity")
		if identityIndex != -1 {
			dm.Identity = matches[identityIndex]
		}

		rcodeIndex := re.SubexpIndex("rcode")
		if rcodeIndex != -1 {
			dm.Rcode = matches[rcodeIndex]
		}

		queryipIndex := re.SubexpIndex("queryip")
		if queryipIndex != -1 {
			dm.QueryIp = matches[queryipIndex]
		}

		queryportIndex := re.SubexpIndex("queryport")
		if queryportIndex != -1 {
			dm.QueryPort = matches[queryportIndex]
		}

		responseipIndex := re.SubexpIndex("responseip")
		if responseipIndex != -1 {
			dm.ResponseIp = matches[responseipIndex]
		}

		responseportIndex := re.SubexpIndex("responseport")
		if responseportIndex != -1 {
			dm.ResponsePort = matches[responseportIndex]
		}

		familyIndex := re.SubexpIndex("family")
		if familyIndex != -1 {
			dm.Family = matches[familyIndex]
		} else {
			dm.Family = "INET"
		}

		protocolIndex := re.SubexpIndex("protocol")
		if protocolIndex != -1 {
			dm.Protocol = matches[protocolIndex]
		} else {
			dm.Protocol = "UDP"
		}

		lengthIndex := re.SubexpIndex("length")
		if lengthIndex != -1 {
			length, err := strconv.Atoi(matches[lengthIndex])
			if err == nil {
				dm.Length = length
			}
		}

		domainIndex := re.SubexpIndex("domain")
		if domainIndex != -1 {
			dm.Qname = matches[domainIndex]
		}

		qtypeIndex := re.SubexpIndex("qtype")
		if qtypeIndex != -1 {
			dm.Qtype = matches[qtypeIndex]
		}

		latencyIndex := re.SubexpIndex("latency")
		if latencyIndex != -1 {
			dm.LatencySec = matches[latencyIndex]
		}

		// compute timestamp
		dm.Timestamp = float64(dm.TimeSec) + float64(dm.TimeNsec)/1e9
		ts := time.Unix(int64(dm.TimeSec), int64(dm.TimeNsec))
		dm.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

		// fake dns packet
		dnspkt := new(dns.Msg)
		var dnstype uint16
		dnstype = dns.TypeA
		if dm.Qtype == "AAAA" {
			dnstype = dns.TypeAAAA
		}
		dnspkt.SetQuestion(dm.Qname, dnstype)

		if dm.Type == "reply" {
			rr, _ := dns.NewRR(fmt.Sprintf("%s %s 0.0.0.0", dm.Qname, dm.Qtype))
			if err == nil {
				dnspkt.Answer = append(dnspkt.Answer, rr)
			}
			var rcode int
			rcode = 0
			if dm.Rcode == "NXDOMAIN" {
				rcode = 3
			}
			dnspkt.Rcode = rcode
		}

		dm.Payload, _ = dnspkt.Pack()
		dm.Length = len(dm.Payload)

		// filtering
		if filtering.Ignore(&dm) {
			continue
		}

		// geoip feature
		if geoip.IsEnabled() {
			country, err := geoip.Lookup(dm.QueryIp)
			if err != nil {
				c.LogError("geoip loopkup failed: %v+", err)
			}
			dm.CountryIsoCode = country
		}

		// ip anonymisation ?
		if anonIp.IsEnabled() {
			dm.QueryIp = anonIp.Anonymize(dm.QueryIp)
		}

		// send to loggers
		chanLoggers := c.Loggers()
		for i := range chanLoggers {
			chanLoggers[i] <- dm
		}
	}

	c.LogInfo("run terminated")
	c.done <- true
}
