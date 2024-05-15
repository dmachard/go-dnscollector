package workers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"time"

	"strings"

	syslog "github.com/dmachard/go-clientsyslog"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

type Syslog struct {
	*GenericWorker
	severity, facility                 syslog.Priority
	syslogWriter                       *syslog.Writer
	syslogReady                        bool
	transportReady, transportReconnect chan bool
	textFormat                         []string
}

func NewSyslog(config *pkgconfig.Config, console *logger.Logger, name string) *Syslog {
	w := &Syslog{GenericWorker: NewGenericWorker(config, console, name, "syslog", config.Loggers.Syslog.ChannelBufferSize, pkgconfig.DefaultMonitor)}
	w.transportReady = make(chan bool)
	w.transportReconnect = make(chan bool)
	w.ReadConfig()
	return w
}

func (w *Syslog) ReadConfig() {
	if !pkgconfig.IsValidTLS(w.GetConfig().Loggers.Syslog.TLSMinVersion) {
		w.LogFatal(pkgconfig.PrefixLogWorker + "invalid tls min version")
	}

	if !pkgconfig.IsValidMode(w.GetConfig().Loggers.Syslog.Mode) {
		w.LogFatal(pkgconfig.PrefixLogWorker + "invalid mode text or json expected")
	}
	severity, err := syslog.GetPriority(w.GetConfig().Loggers.Syslog.Severity)
	if err != nil {
		w.LogFatal(pkgconfig.PrefixLogWorker + "invalid severity")
	}
	w.severity = severity

	facility, err := syslog.GetPriority(w.GetConfig().Loggers.Syslog.Facility)
	if err != nil {
		w.LogFatal(pkgconfig.PrefixLogWorker + "invalid facility")
	}
	w.facility = facility

	if len(w.GetConfig().Loggers.Syslog.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.Syslog.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}
}

func (w *Syslog) ConnectToRemote() {
	for {
		if w.syslogWriter != nil {
			w.syslogWriter.Close()
			w.syslogWriter = nil
		}

		var logWriter *syslog.Writer
		var tlsConfig *tls.Config
		var err error

		switch w.GetConfig().Loggers.Syslog.Transport {
		case "local":
			w.LogInfo("connecting to local syslog...")
			logWriter, err = syslog.New(w.facility|w.severity, "")
		case netutils.SocketUnix:
			w.LogInfo("connecting to %s://%s ...",
				w.GetConfig().Loggers.Syslog.Transport,
				w.GetConfig().Loggers.Syslog.RemoteAddress)
			logWriter, err = syslog.Dial("",
				w.GetConfig().Loggers.Syslog.RemoteAddress, w.facility|w.severity,
				w.GetConfig().Loggers.Syslog.Tag)
		case netutils.SocketUDP, netutils.SocketTCP:
			w.LogInfo("connecting to %s://%s ...",
				w.GetConfig().Loggers.Syslog.Transport,
				w.GetConfig().Loggers.Syslog.RemoteAddress)
			logWriter, err = syslog.Dial(w.GetConfig().Loggers.Syslog.Transport,
				w.GetConfig().Loggers.Syslog.RemoteAddress, w.facility|w.severity,
				w.GetConfig().Loggers.Syslog.Tag)
		case netutils.SocketTLS:
			w.LogInfo("connecting to %s://%s ...",
				w.GetConfig().Loggers.Syslog.Transport,
				w.GetConfig().Loggers.Syslog.RemoteAddress)

			tlsOptions := pkgconfig.TLSOptions{
				InsecureSkipVerify: w.GetConfig().Loggers.Syslog.TLSInsecure,
				MinVersion:         w.GetConfig().Loggers.Syslog.TLSMinVersion,
				CAFile:             w.GetConfig().Loggers.Syslog.CAFile,
				CertFile:           w.GetConfig().Loggers.Syslog.CertFile,
				KeyFile:            w.GetConfig().Loggers.Syslog.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
			if err == nil {
				logWriter, err = syslog.DialWithTLSConfig(w.GetConfig().Loggers.Syslog.Transport,
					w.GetConfig().Loggers.Syslog.RemoteAddress, w.facility|w.severity,
					w.GetConfig().Loggers.Syslog.Tag,
					tlsConfig)
			}
		default:
			w.LogFatal("invalid syslog transport: ", w.GetConfig().Loggers.Syslog.Transport)
		}

		// something is wrong during connection ?
		if err != nil {
			w.LogError("%s", err)
			w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.Syslog.RetryInterval)
			time.Sleep(time.Duration(w.GetConfig().Loggers.Syslog.RetryInterval) * time.Second)
			continue
		}

		w.syslogWriter = logWriter

		// set syslog format
		switch strings.ToLower(w.GetConfig().Loggers.Syslog.Formatter) {
		case "unix":
			w.syslogWriter.SetFormatter(syslog.UnixFormatter)
		case "rfc3164":
			w.syslogWriter.SetFormatter(syslog.RFC3164Formatter)
		case "rfc5424", "":
			w.syslogWriter.SetFormatter(syslog.RFC5424Formatter)
		}

		// set syslog framer
		switch strings.ToLower(w.GetConfig().Loggers.Syslog.Framer) {
		case "none", "":
			w.syslogWriter.SetFramer(syslog.DefaultFramer)
		case "rfc5425":
			w.syslogWriter.SetFramer(syslog.RFC5425MessageLengthFramer)
		}

		// custom hostname
		if len(w.GetConfig().Loggers.Syslog.Hostname) > 0 {
			w.syslogWriter.SetHostname(w.GetConfig().Loggers.Syslog.Hostname)
		}
		// custom program name
		if len(w.GetConfig().Loggers.Syslog.AppName) > 0 {
			w.syslogWriter.SetProgram(w.GetConfig().Loggers.Syslog.AppName)
		}

		// notify process that the transport is ready
		// block the loop until a reconnect is needed
		w.transportReady <- true
		w.transportReconnect <- true
	}
}

func (w *Syslog) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// init remote conn
	go w.ConnectToRemote()

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
				w.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *Syslog) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	buffer := new(bytes.Buffer)
	var err error

	for _, dm := range *buf {
		switch w.GetConfig().Loggers.Syslog.Mode {
		case pkgconfig.ModeText:
			// write the text line to the buffer
			buffer.Write(dm.Bytes(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary))

			// replace NULL char from text line directly in the buffer
			// because the NULL is a end of log in syslog
			for i := 0; i < buffer.Len(); i++ {
				if buffer.Bytes()[i] == 0 {
					buffer.Bytes()[i] = w.GetConfig().Loggers.Syslog.ReplaceNullChar[0]
				}
			}

			// ensure it ends in a \n
			buffer.WriteString("\n")

			// write the modified content of the buffer to s.syslogWriter
			// and reset the buffer
			_, err = buffer.WriteTo(w.syslogWriter)

		case pkgconfig.ModeJSON:
			// encode to json the dns message
			json.NewEncoder(buffer).Encode(dm)

			// write the content of the buffer to s.syslogWriter
			// and reset the buffer
			_, err = buffer.WriteTo(w.syslogWriter)

		case pkgconfig.ModeFlatJSON:
			// get flatten object
			flat, errflat := dm.Flatten()
			if errflat != nil {
				w.LogError("flattening DNS message failed: %e", err)
				continue
			}

			// encode to json
			json.NewEncoder(buffer).Encode(flat)

			// write the content of the buffer to s.syslogWriter
			// and reset the buffer
			_, err = buffer.WriteTo(w.syslogWriter)
		}

		if err != nil {
			w.LogError("write error %s", err)
			w.syslogReady = false
			<-w.transportReconnect
			break
		}
	}

	// reset buffer
	*buf = nil
}

func (w *Syslog) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(w.GetConfig().Loggers.Syslog.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	w.LogInfo("processing dns messages...")
	for {
		select {
		case <-w.OnLoggerStopped():
			// close connection
			if w.syslogWriter != nil {
				w.syslogWriter.Close()
			}
			return

		case <-w.transportReady:
			w.LogInfo("syslog transport is ready")
			w.syslogReady = true

			// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// discar dns message if the connection is not ready
			if !w.syslogReady {
				continue
			}
			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= w.GetConfig().Loggers.Syslog.BufferSize {
				w.FlushBuffer(&bufferDm)
			}

			// flush the buffer
		case <-flushTimer.C:
			if !w.syslogReady {
				bufferDm = nil
			}

			if len(bufferDm) > 0 {
				w.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
}
