package workers

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/hpcloud/tail"
	"github.com/miekg/dns"
)

type Tail struct {
	*GenericWorker
	tailf *tail.Tail
}

func NewTail(next []Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *Tail {
	w := &Tail{GenericWorker: NewGenericWorker(config, logger, name, "tail", pkgconfig.DefaultBufferSize, pkgconfig.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	return w
}

func (w *Tail) Follow() error {
	var err error
	location := tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}
	config := tail.Config{Location: &location, ReOpen: true, Follow: true, Logger: tail.DiscardingLogger, Poll: true, MustExist: true}
	w.tailf, err = tail.TailFile(w.GetConfig().Collectors.Tail.FilePath, config)
	if err != nil {
		return err
	}
	return nil
}

func (w *Tail) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	err := w.Follow()
	if err != nil {
		w.LogFatal("collector tail - unable to follow file: ", err)
	}

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())
	subprocessors := transformers.NewTransforms(&w.GetConfig().IngoingTransformers, w.GetLogger(), w.GetName(), defaultRoutes, 0)

	// init dns message
	dm := dnsutils.DNSMessage{}
	dm.Init()

	// init dns message with additionnals parts
	hostname, err := os.Hostname()
	if err == nil {
		dm.DNSTap.Identity = hostname
	} else {
		dm.DNSTap.Identity = "undefined"
	}

	for {
		select {
		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			subprocessors.ReloadConfig(&cfg.IngoingTransformers)

		case <-w.OnStop():
			w.LogInfo("stopping...")
			subprocessors.Reset()
			return

		case line := <-w.tailf.Lines:
			var matches []string
			var re *regexp.Regexp

			if len(w.GetConfig().Collectors.Tail.PatternQuery) > 0 {
				re = regexp.MustCompile(w.GetConfig().Collectors.Tail.PatternQuery)
				matches = re.FindStringSubmatch(line.Text)
				dm.DNS.Type = dnsutils.DNSQuery
				dm.DNSTap.Operation = dnsutils.DNSTapOperationQuery
			}

			if len(w.GetConfig().Collectors.Tail.PatternReply) > 0 && len(matches) == 0 {
				re = regexp.MustCompile(w.GetConfig().Collectors.Tail.PatternReply)
				matches = re.FindStringSubmatch(line.Text)
				dm.DNS.Type = dnsutils.DNSReply
				dm.DNSTap.Operation = dnsutils.DNSTapOperationReply
			}

			if len(matches) == 0 {
				continue
			}

			qrIndex := re.SubexpIndex("qr")
			if qrIndex != -1 {
				dm.DNSTap.Operation = matches[qrIndex]
			}

			var t time.Time
			timestampIndex := re.SubexpIndex("timestamp")
			if timestampIndex != -1 {
				t, err = time.Parse(w.GetConfig().Collectors.Tail.TimeLayout, matches[timestampIndex])
				if err != nil {
					continue
				}
			} else {
				t = time.Now()
			}
			dm.DNSTap.TimeSec = int(t.Unix())
			dm.DNSTap.TimeNsec = int(t.UnixNano() - t.Unix()*1e9)

			identityIndex := re.SubexpIndex("identity")
			if identityIndex != -1 {
				dm.DNSTap.Identity = matches[identityIndex]
			}

			rcodeIndex := re.SubexpIndex("rcode")
			if rcodeIndex != -1 {
				dm.DNS.Rcode = matches[rcodeIndex]
			}

			queryipIndex := re.SubexpIndex("queryip")
			if queryipIndex != -1 {
				dm.NetworkInfo.QueryIP = matches[queryipIndex]
			}

			queryportIndex := re.SubexpIndex("queryport")
			if queryportIndex != -1 {
				dm.NetworkInfo.QueryPort = matches[queryportIndex]
			} else {
				dm.NetworkInfo.ResponsePort = "0"
			}

			responseipIndex := re.SubexpIndex("responseip")
			if responseipIndex != -1 {
				dm.NetworkInfo.ResponseIP = matches[responseipIndex]
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
				dm.NetworkInfo.Family = netutils.ProtoIPv4
			}

			protocolIndex := re.SubexpIndex("protocol")
			if protocolIndex != -1 {
				dm.NetworkInfo.Protocol = matches[protocolIndex]
			} else {
				dm.NetworkInfo.Protocol = netutils.ProtoUDP
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
				dm.DNSTap.LatencySec = matches[latencyIndex]
			}

			// compute timestamp
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			dm.DNSTap.Timestamp = ts.UnixNano()
			dm.DNSTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

			// fake dns packet
			dnspkt := new(dns.Msg)
			var dnstype uint16
			dnstype = dns.TypeA
			if dm.DNS.Qtype == "AAAA" {
				dnstype = dns.TypeAAAA
			}
			dnspkt.SetQuestion(dm.DNS.Qname, dnstype)

			if dm.DNS.Type == dnsutils.DNSReply {
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
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			w.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}
