package loggers

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func IsStdoutValidMode(mode string) bool {
	switch mode {
	case
		pkgconfig.ModeText,
		pkgconfig.ModeJSON,
		pkgconfig.ModeFlatJSON,
		pkgconfig.ModePCAP:
		return true
	}
	return false
}

type StdOut struct {
	stopProcess    chan bool
	doneProcess    chan bool
	stopRun        chan bool
	doneRun        chan bool
	inputChan      chan dnsutils.DNSMessage
	outputChan     chan dnsutils.DNSMessage
	textFormat     []string
	config         *pkgconfig.Config
	configChan     chan *pkgconfig.Config
	logger         *logger.Logger
	writerText     *log.Logger
	writerPcap     *pcapgo.Writer
	name           string
	RoutingHandler pkgutils.RoutingHandler
}

func NewStdOut(config *pkgconfig.Config, console *logger.Logger, name string) *StdOut {
	console.Info(pkgutils.PrefixLogLogger+"[%s] stdout - enabled", name)
	so := &StdOut{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.Stdout.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.Stdout.ChannelBufferSize),
		logger:         console,
		config:         config,
		configChan:     make(chan *pkgconfig.Config),
		writerText:     log.New(os.Stdout, "", 0),
		name:           name,
		RoutingHandler: pkgutils.NewRoutingHandler(config, console, name),
	}
	so.ReadConfig()
	return so
}

func (so *StdOut) GetName() string { return so.name }

func (so *StdOut) AddDroppedRoute(wrk pkgutils.Worker) {
	so.RoutingHandler.AddDroppedRoute(wrk)
}

func (so *StdOut) AddDefaultRoute(wrk pkgutils.Worker) {
	so.RoutingHandler.AddDefaultRoute(wrk)
}

func (so *StdOut) SetLoggers(loggers []pkgutils.Worker) {}

func (so *StdOut) ReadConfig() {
	if !IsStdoutValidMode(so.config.Loggers.Stdout.Mode) {
		so.logger.Fatal("["+so.name+"] logger=stdout - invalid mode: ", so.config.Loggers.Stdout.Mode)
	}

	if len(so.config.Loggers.Stdout.TextFormat) > 0 {
		//  so.textFormat = strings.Fields(so.config.Loggers.Stdout.TextFormat)
		so.textFormat = strings.Split(so.config.Loggers.Stdout.TextFormat,so.config.Global.TextFormatSplitter)
	} else {
		// so.textFormat = strings.Fields(so.config.Global.TextFormat)
		so.textFormat = strings.Split(so.config.Global.TextFormat,so.config.Global.TextFormatSplitter)
	}
	so.logger.Info("textFormat = "+so.config.Global.TextFormat)
}

func (so *StdOut) ReloadConfig(config *pkgconfig.Config) {
	so.LogInfo("reload configuration!")
	so.configChan <- config
}

func (so *StdOut) LogInfo(msg string, v ...interface{}) {
	so.logger.Info(pkgutils.PrefixLogLogger+"["+so.name+"] stdout - "+msg, v...)
}

func (so *StdOut) LogError(msg string, v ...interface{}) {
	so.logger.Error(pkgutils.PrefixLogLogger+"["+so.name+"] stdout - "+msg, v...)
}

func (so *StdOut) SetTextWriter(b *bytes.Buffer) {
	so.writerText = log.New(os.Stdout, "", 0)
	so.writerText.SetOutput(b)
}

func (so *StdOut) SetPcapWriter(w io.Writer) {
	so.LogInfo("init pcap writer")

	so.writerPcap = pcapgo.NewWriter(w)
	if err := so.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		so.logger.Fatal("["+so.name+"] logger=stdout - pcap init error: %e", err)
	}
}

func (so *StdOut) GetInputChannel() chan dnsutils.DNSMessage {
	return so.inputChan
}

func (so *StdOut) Stop() {
	so.LogInfo("stopping logger...")
	so.RoutingHandler.Stop()

	so.LogInfo("stopping to run...")
	so.stopRun <- true
	<-so.doneRun

	so.LogInfo("stopping to process...")
	so.stopProcess <- true
	<-so.doneProcess
}

func (so *StdOut) Run() {
	so.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := so.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := so.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, so.outputChan)
	subprocessors := transformers.NewTransforms(&so.config.OutgoingTransformers, so.logger, so.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go so.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-so.stopRun:
			// cleanup transformers
			subprocessors.Reset()
			so.doneRun <- true
			break RUN_LOOP

		// new config provided?
		case cfg, opened := <-so.configChan:
			if !opened {
				return
			}
			so.config = cfg
			so.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-so.inputChan:
			if !opened {
				so.LogInfo("run: input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				so.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			so.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			so.outputChan <- dm
		}
	}
	so.LogInfo("run terminated")
}

func (so *StdOut) Process() {

	// standard output buffer
	buffer := new(bytes.Buffer)

	if so.config.Loggers.Stdout.Mode == pkgconfig.ModePCAP && so.writerPcap == nil {
		so.SetPcapWriter(os.Stdout)
	}

	so.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-so.stopProcess:
			so.doneProcess <- true
			break PROCESS_LOOP

		case dm, opened := <-so.outputChan:
			if !opened {
				so.LogInfo("process: output channel closed!")
				return
			}

			switch so.config.Loggers.Stdout.Mode {
			case pkgconfig.ModePCAP:
				if len(dm.DNS.Payload) == 0 {
					so.LogError("process: no dns payload to encode, drop it")
					continue
				}

				pkt, err := dm.ToPacketLayer()
				if err != nil {
					so.LogError("unable to pack layer: %s", err)
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
					Timestamp:     time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec)),
					CaptureLength: bufSize,
					Length:        bufSize,
				}

				so.writerPcap.WritePacket(ci, buf.Bytes())

			case pkgconfig.ModeText:
				so.writerText.Print(dm.String(so.textFormat,
					so.config.Global.TextFormatDelimiter,
					so.config.Global.TextFormatBoundary))

			case pkgconfig.ModeJSON:
				json.NewEncoder(buffer).Encode(dm)
				so.writerText.Print(buffer.String())
				buffer.Reset()

			case pkgconfig.ModeFlatJSON:
				flat, err := dm.Flatten()
				if err != nil {
					so.LogError("process: flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				so.writerText.Print(buffer.String())
				buffer.Reset()
			}
		}
	}
	so.LogInfo("processing terminated")
}
