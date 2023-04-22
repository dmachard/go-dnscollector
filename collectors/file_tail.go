package collectors

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
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
	name    string
}

func NewTail(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *Tail {
	logger.Info("[%s] tail collector - enabled", name)
	s := &Tail{
		done:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
		name:    name,
	}
	s.ReadConfig()
	return s
}

func (c *Tail) GetName() string { return c.name }

func (c *Tail) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
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

func (c *Tail) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] tail collector - "+msg, v...)
}

func (c *Tail) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] tail collector - "+msg, v...)
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
	location := tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}
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
		c.logger.Fatal("collector tail - unable to follow file: ", err)
	}

	// prepare enabled transformers
	subprocessors := transformers.NewTransforms(&c.config.IngoingTransformers, c.logger, c.name, c.Loggers())

	// init dns message
	dm := dnsutils.DnsMessage{}
	dm.Init()

	// init dns message with additionnals parts
	subprocessors.InitDnsMessageFormat(&dm)

	hostname, err := os.Hostname()
	if err == nil {
		dm.DnsTap.Identity = hostname
	} else {
		dm.DnsTap.Identity = "undefined"
	}

	for line := range c.tailf.Lines {
		var matches []string
		var re *regexp.Regexp

		if len(c.config.Collectors.Tail.PatternQuery) > 0 {
			re = regexp.MustCompile(c.config.Collectors.Tail.PatternQuery)
			matches = re.FindStringSubmatch(line.Text)
			dm.DNS.Type = dnsutils.DnsQuery
			dm.DnsTap.Operation = dnsutils.DNSTAP_OPERATION_QUERY
		}

		if len(c.config.Collectors.Tail.PatternReply) > 0 && len(matches) == 0 {
			re = regexp.MustCompile(c.config.Collectors.Tail.PatternReply)
			matches = re.FindStringSubmatch(line.Text)
			dm.DNS.Type = dnsutils.DnsReply
			dm.DnsTap.Operation = dnsutils.DNSTAP_OPERATION_REPLY
		}

		if len(matches) == 0 {
			continue
		}

		qrIndex := re.SubexpIndex("qr")
		if qrIndex != -1 {
			dm.DnsTap.Operation = matches[qrIndex]
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
		dm.DnsTap.TimeSec = int(t.Unix())
		dm.DnsTap.TimeNsec = int(t.UnixNano() - t.Unix()*1e9)

		identityIndex := re.SubexpIndex("identity")
		if identityIndex != -1 {
			dm.DnsTap.Identity = matches[identityIndex]
		}

		rcodeIndex := re.SubexpIndex("rcode")
		if rcodeIndex != -1 {
			dm.DNS.Rcode = matches[rcodeIndex]
		}

		queryipIndex := re.SubexpIndex("queryip")
		if queryipIndex != -1 {
			dm.NetworkInfo.QueryIp = matches[queryipIndex]
		}

		queryportIndex := re.SubexpIndex("queryport")
		if queryportIndex != -1 {
			dm.NetworkInfo.QueryPort = matches[queryportIndex]
		} else {
			dm.NetworkInfo.ResponsePort = "0"
		}

		responseipIndex := re.SubexpIndex("responseip")
		if responseipIndex != -1 {
			dm.NetworkInfo.ResponseIp = matches[responseipIndex]
		}

		responseportIndex := re.SubexpIndex("responseport")
		if responseportIndex != -1 {
			dm.NetworkInfo.ResponsePort = matches[responseportIndex]
		} else {
			dm.NetworkInfo.ResponsePort = "0"
		}

		familyIndex := re.SubexpIndex("family")
		if familyIndex != -1 {
			dm.NetworkInfo.Family = matches[familyIndex]
		} else {
			dm.NetworkInfo.Family = dnsutils.PROTO_IPV4
		}

		protocolIndex := re.SubexpIndex("protocol")
		if protocolIndex != -1 {
			dm.NetworkInfo.Protocol = matches[protocolIndex]
		} else {
			dm.NetworkInfo.Protocol = dnsutils.PROTO_UDP
		}

		lengthIndex := re.SubexpIndex("length")
		if lengthIndex != -1 {
			length, err := strconv.Atoi(matches[lengthIndex])
			if err == nil {
				dm.DNS.Length = length
			}
		}

		domainIndex := re.SubexpIndex("domain")
		if domainIndex != -1 {
			dm.DNS.Qname = matches[domainIndex]
		}

		qtypeIndex := re.SubexpIndex("qtype")
		if qtypeIndex != -1 {
			dm.DNS.Qtype = matches[qtypeIndex]
		}

		latencyIndex := re.SubexpIndex("latency")
		if latencyIndex != -1 {
			dm.DnsTap.LatencySec = matches[latencyIndex]
		}

		// compute timestamp
		ts := time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))
		dm.DnsTap.Timestamp = ts.UnixNano()
		dm.DnsTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

		// fake dns packet
		dnspkt := new(dns.Msg)
		var dnstype uint16
		dnstype = dns.TypeA
		if dm.DNS.Qtype == "AAAA" {
			dnstype = dns.TypeAAAA
		}
		dnspkt.SetQuestion(dm.DNS.Qname, dnstype)

		if dm.DNS.Type == dnsutils.DnsReply {
			rr, _ := dns.NewRR(fmt.Sprintf("%s %s 0.0.0.0", dm.DNS.Qname, dm.DNS.Qtype))
			if err == nil {
				dnspkt.Answer = append(dnspkt.Answer, rr)
			}
			var rcode int
			rcode = 0
			if dm.DNS.Rcode == "NXDOMAIN" {
				rcode = 3
			}
			dnspkt.Rcode = rcode
		}

		dm.DNS.Payload, _ = dnspkt.Pack()
		dm.DNS.Length = len(dm.DNS.Payload)

		// apply all enabled transformers
		if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
			continue
		}

		// send to loggers
		chanLoggers := c.Loggers()
		for i := range chanLoggers {
			chanLoggers[i] <- dm
		}
	}

	// cleanup transformers
	subprocessors.Reset()

	c.LogInfo("run terminated")
	c.done <- true
}
