package loggers

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func IsStdoutValidMode(mode string) bool {
	switch mode {
	case
		dnsutils.MODE_TEXT,
		dnsutils.MODE_JSON,
		dnsutils.MODE_FLATJSON,
		dnsutils.MODE_PCAP:
		return true
	}
	return false
}

type StdOut struct {
	stopProcess chan bool
	doneProcess chan bool
	stopRun     chan bool
	doneRun     chan bool
	inputChan   chan dnsutils.DnsMessage
	outputChan  chan dnsutils.DnsMessage
	textFormat  []string
	config      *dnsutils.Config
	configChan  chan *dnsutils.Config
	logger      *logger.Logger
	stdout      *log.Logger
	name        string
}

func NewStdOut(config *dnsutils.Config, console *logger.Logger, name string) *StdOut {
	console.Info("[%s] logger=stdout - enabled", name)
	o := &StdOut{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DnsMessage, config.Loggers.Stdout.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DnsMessage, config.Loggers.Stdout.ChannelBufferSize),
		logger:      console,
		config:      config,
		configChan:  make(chan *dnsutils.Config),
		stdout:      log.New(os.Stdout, "", 0),
		name:        name,
	}
	o.ReadConfig()
	return o
}

func (c *StdOut) GetName() string { return c.name }

func (c *StdOut) SetLoggers(loggers []dnsutils.Worker) {}

func (c *StdOut) ReadConfig() {
	if !IsStdoutValidMode(c.config.Loggers.Stdout.Mode) {
		c.logger.Fatal("["+c.name+"] logger=stdout - invalid mode: ", c.config.Loggers.Stdout.Mode)
	}
	if len(c.config.Loggers.Stdout.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.Stdout.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}
}

func (o *StdOut) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload configuration!")
	o.configChan <- config
}

func (c *StdOut) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=stdout - "+msg, v...)
}

func (c *StdOut) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=stdout - "+msg, v...)
}

func (o *StdOut) SetBuffer(b *bytes.Buffer) {
	o.stdout.SetOutput(b)
}

func (o *StdOut) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *StdOut) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *StdOut) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.outputChan)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go o.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-o.stopRun:
			// cleanup transformers
			subprocessors.Reset()
			o.doneRun <- true
			break RUN_LOOP

		// new config provided?
		case cfg, opened := <-o.configChan:
			if !opened {
				return
			}
			o.config = cfg
			o.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-o.inputChan:
			if !opened {
				o.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDnsMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// send to output channel
			o.outputChan <- dm
		}
	}
	o.LogInfo("run terminated")
}

func (o *StdOut) Process() {

	// standard output buffer
	buffer := new(bytes.Buffer)

	// pcap init ?
	var writerPcap *pcapgo.Writer
	if o.config.Loggers.Stdout.Mode == dnsutils.MODE_PCAP {
		writerPcap = pcapgo.NewWriter(os.Stdout)
		if err := writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			o.LogError("pcap init error: %e", err)
		}
	}

	o.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			o.doneProcess <- true
			break PROCESS_LOOP

		case dm, opened := <-o.outputChan:
			if !opened {
				o.LogInfo("output channel closed!")
				return
			}

			switch o.config.Loggers.Stdout.Mode {
			case dnsutils.MODE_PCAP:
				pkt, err := dm.ToPacketLayer()
				if err != nil {
					o.LogError("failed to encode to packet layer: %s", err)
					continue
				}

				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				for _, l := range pkt {
					l.SerializeTo(buf, opts)
				}

				bufSize := len(buf.Bytes())
				ci := gopacket.CaptureInfo{
					Timestamp:     time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec)),
					CaptureLength: bufSize,
					Length:        bufSize,
				}

				writerPcap.WritePacket(ci, buf.Bytes())

			case dnsutils.MODE_TEXT:
				o.stdout.Print(dm.String(o.textFormat,
					o.config.Global.TextFormatDelimiter,
					o.config.Global.TextFormatBoundary))

			case dnsutils.MODE_JSON:
				json.NewEncoder(buffer).Encode(dm)
				o.stdout.Print(buffer.String())
				buffer.Reset()

			case dnsutils.MODE_FLATJSON:
				flat, err := dm.Flatten()
				if err != nil {
					o.LogError("flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				o.stdout.Print(buffer.String())
				buffer.Reset()
			}
		}
	}
	o.LogInfo("processing terminated")
}
