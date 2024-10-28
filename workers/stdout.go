package workers

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func IsStdoutValidMode(mode string) bool {
	switch mode {
	case
		pkgconfig.ModeJinja,
		pkgconfig.ModeText,
		pkgconfig.ModeJSON,
		pkgconfig.ModeFlatJSON,
		pkgconfig.ModePCAP:
		return true
	}
	return false
}

type StdOut struct {
	*GenericWorker
	textFormat  []string
	jinjaFormat string
	writerText  *log.Logger
	writerPcap  *pcapgo.Writer
}

func NewStdOut(config *pkgconfig.Config, console *logger.Logger, name string) *StdOut {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Loggers.Stdout.ChannelBufferSize > 0 {
		bufSize = config.Loggers.Stdout.ChannelBufferSize
	}
	w := &StdOut{GenericWorker: NewGenericWorker(config, console, name, "stdout", bufSize, pkgconfig.DefaultMonitor)}
	w.writerText = log.New(os.Stdout, "", 0)
	w.ReadConfig()
	return w
}

func (w *StdOut) ReadConfig() {
	if !IsStdoutValidMode(w.GetConfig().Loggers.Stdout.Mode) {
		w.LogFatal("invalid mode: ", w.GetConfig().Loggers.Stdout.Mode)
	}

	if len(w.GetConfig().Loggers.Stdout.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.Stdout.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	if len(w.GetConfig().Loggers.Stdout.JinjaFormat) > 0 {
		w.jinjaFormat = w.GetConfig().Loggers.Stdout.JinjaFormat
	} else {
		w.jinjaFormat = w.GetConfig().Global.TextJinja
	}
}

func (w *StdOut) SetTextWriter(b *bytes.Buffer) {
	w.writerText = log.New(os.Stdout, "", 0)
	w.writerText.SetOutput(b)
}

func (w *StdOut) SetPcapWriter(pcapWriter io.Writer) {
	w.LogInfo("init pcap writer")

	w.writerPcap = pcapgo.NewWriter(pcapWriter)
	if err := w.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		w.LogFatal("pcap init error", err)
	}
}

func (w *StdOut) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

		// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("run: input channel closed!")
				return
			}

			// count global messages
			w.CountIngressTraffic()

			// apply tranforms, init dns message with additionnals parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.CountEgressTraffic()
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *StdOut) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// standard output buffer
	buffer := new(bytes.Buffer)

	if w.GetConfig().Loggers.Stdout.Mode == pkgconfig.ModePCAP && w.writerPcap == nil {
		w.SetPcapWriter(os.Stdout)
	}

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("process: output channel closed!")
				return
			}

			switch w.GetConfig().Loggers.Stdout.Mode {
			case pkgconfig.ModePCAP:
				if len(dm.DNS.Payload) == 0 {
					w.LogError("process: no dns payload to encode, drop it")
					continue
				}

				pkt, err := dm.ToPacketLayer()
				if err != nil {
					w.LogError("process: unable to pack layer: %s", err)
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

				w.writerPcap.WritePacket(ci, buf.Bytes())

			case pkgconfig.ModeText:
				w.writerText.Print(dm.String(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary))

			case pkgconfig.ModeJinja:
				textLine, err := dm.ToTextTemplate(w.jinjaFormat)
				if err != nil {
					w.LogError("process: unable to update template: %s", err)
					continue
				}
				w.writerText.Print(textLine)

			case pkgconfig.ModeJSON:
				json.NewEncoder(buffer).Encode(dm)
				w.writerText.Print(buffer.String())
				buffer.Reset()

			case pkgconfig.ModeFlatJSON:
				flat, err := dm.Flatten()
				if err != nil {
					w.LogError("process: flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				w.writerText.Print(buffer.String())
				buffer.Reset()
			}
		}
	}
}
