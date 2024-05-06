package loggers

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	*pkgutils.GenericWorker
	textFormat []string
	writerText *log.Logger
	writerPcap *pcapgo.Writer
}

func NewStdOut(config *pkgconfig.Config, console *logger.Logger, name string) *StdOut {
	s := &StdOut{GenericWorker: pkgutils.NewGenericWorker(config, console, name, "stdout", config.Loggers.Stdout.ChannelBufferSize)}
	s.writerText = log.New(os.Stdout, "", 0)
	s.ReadConfig()
	return s
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
	w.LogInfo("worker is starting collection")
	defer func() {
		w.StopIsDone()
	}()

	// prepare next channels
	defaultRoutes, defaultNames := pkgutils.GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := pkgutils.GetRoutes(w.GetDefaultRoutes())

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, w.GetOutputChannel())
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), listChannel, 0)

	// // goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	// RUN_LOOP:
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

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				for i := range droppedRoutes {
					select {
					case droppedRoutes[i] <- dm:
					default:
						w.WorkerIsBusy(droppedNames[i])
					}
				}
				continue
			}

			// send to output channel
			fmt.Println(dm)
			w.GetOutputChannel() <- dm

			// send to next ?
			for i := range defaultRoutes {
				select {
				case defaultRoutes[i] <- dm:
				default:
					w.WorkerIsBusy(defaultNames[i])
				}
			}
		}
	}
}

func (w *StdOut) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer func() {
		w.LoggerTerminated()
	}()

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
