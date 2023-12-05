package processors

import (
	"fmt"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/miekg/dns"
)

func GetFakeDNS() ([]byte, error) {
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dns.collector.", dns.TypeA)
	return dnsmsg.Pack()
}

type DNSProcessor struct {
	doneRun      chan bool
	stopRun      chan bool
	doneMonitor  chan bool
	stopMonitor  chan bool
	recvFrom     chan dnsutils.DNSMessage
	logger       *logger.Logger
	config       *pkgconfig.Config
	ConfigChan   chan *pkgconfig.Config
	name         string
	dropped      chan string
	droppedCount map[string]int
}

func NewDNSProcessor(config *pkgconfig.Config, logger *logger.Logger, name string, size int) DNSProcessor {
	logger.Info("[%s] processor=dns - initialization...", name)
	d := DNSProcessor{
		doneMonitor:  make(chan bool),
		doneRun:      make(chan bool),
		stopMonitor:  make(chan bool),
		stopRun:      make(chan bool),
		recvFrom:     make(chan dnsutils.DNSMessage, size),
		logger:       logger,
		config:       config,
		ConfigChan:   make(chan *pkgconfig.Config),
		name:         name,
		dropped:      make(chan string),
		droppedCount: map[string]int{},
	}
	return d
}

func (d *DNSProcessor) LogInfo(msg string, v ...interface{}) {
	d.logger.Info("["+d.name+"] processor=dns - "+msg, v...)
}

func (d *DNSProcessor) LogError(msg string, v ...interface{}) {
	d.logger.Error("["+d.name+"] processor=dns - "+msg, v...)
}

func (d *DNSProcessor) GetChannel() chan dnsutils.DNSMessage {
	return d.recvFrom
}

func (d *DNSProcessor) GetChannelList() []chan dnsutils.DNSMessage {
	channel := []chan dnsutils.DNSMessage{}
	channel = append(channel, d.recvFrom)
	return channel
}

func (d *DNSProcessor) Stop() {
	d.LogInfo("stopping to process...")
	d.stopRun <- true
	<-d.doneRun

	d.LogInfo("stopping to monitor loggers...")
	d.stopMonitor <- true
	<-d.doneMonitor
}

func (d *DNSProcessor) MonitorLoggers() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
FOLLOW_LOOP:
	for {
		select {
		case <-d.stopMonitor:
			close(d.dropped)
			bufferFull.Stop()
			d.doneMonitor <- true
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
	d.LogInfo("monitor terminated")
}

func (d *DNSProcessor) Run(loggersChannel []chan dnsutils.DNSMessage, loggersName []string) {
	// prepare enabled transformers
	transforms := transformers.NewTransforms(&d.config.IngoingTransformers, d.logger, d.name, loggersChannel, 0)

	// start goroutine to count dropped messsages
	go d.MonitorLoggers()

	// read incoming dns message
	d.LogInfo("waiting dns message to process...")
RUN_LOOP:
	for {
		select {
		case cfg := <-d.ConfigChan:
			d.config = cfg
			transforms.ReloadConfig(&cfg.IngoingTransformers)

		case <-d.stopRun:
			transforms.Reset()
			d.doneRun <- true
			break RUN_LOOP

		case dm, opened := <-d.recvFrom:
			if !opened {
				d.LogInfo("channel closed, exit")
				return
			}

			// init dns message with additionnals parts
			transforms.InitDNSMessageFormat(&dm)

			// compute timestamp
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			dm.DNSTap.Timestamp = ts.UnixNano()
			dm.DNSTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

			// decode the dns payload
			dnsHeader, err := dnsutils.DecodeDNS(dm.DNS.Payload)
			if err != nil {
				dm.DNS.MalformedPacket = true
				d.LogError("dns parser malformed packet: %s - %v+", err, dm)
			}

			// dns reply ?
			if dnsHeader.Qr == 1 {
				dm.DNSTap.Operation = "CLIENT_RESPONSE"
				dm.DNS.Type = dnsutils.DNSReply
				qip := dm.NetworkInfo.QueryIP
				qport := dm.NetworkInfo.QueryPort
				dm.NetworkInfo.QueryIP = dm.NetworkInfo.ResponseIP
				dm.NetworkInfo.QueryPort = dm.NetworkInfo.ResponsePort
				dm.NetworkInfo.ResponseIP = qip
				dm.NetworkInfo.ResponsePort = qport
			} else {
				dm.DNS.Type = dnsutils.DNSQuery
				dm.DNSTap.Operation = dnsutils.DNSTapClientQuery
			}

			if err = dnsutils.DecodePayload(&dm, &dnsHeader, d.config); err != nil {
				d.LogError("%v - %v", err, dm)
			}

			if dm.DNS.MalformedPacket {
				if d.config.Global.Trace.LogMalformed {
					d.LogInfo("payload: %v", dm.DNS.Payload)
				}
			}

			// apply all enabled transformers
			if transforms.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// convert latency to human
			dm.DNSTap.LatencySec = fmt.Sprintf("%.6f", dm.DNSTap.Latency)

			// dispatch dns message to all generators
			for i := range loggersChannel {
				select {
				case loggersChannel[i] <- dm: // Successful send to logger channel
				default:
					d.dropped <- loggersName[i]
				}
			}
		}
	}
	d.LogInfo("processing terminated")
}
