package loggers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"strings"

	syslog "github.com/dmachard/go-clientsyslog"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

func GetPriority(facility string) (syslog.Priority, error) {
	facility = strings.ToUpper(facility)
	switch facility {
	// level
	case "WARNING":
		return syslog.LOG_WARNING, nil
	case "NOTICE":
		return syslog.LOG_NOTICE, nil
	case "INFO":
		return syslog.LOG_INFO, nil
	case "DEBUG":
		return syslog.LOG_DEBUG, nil
	// facility
	case "DAEMON":
		return syslog.LOG_DAEMON, nil
	case "LOCAL0":
		return syslog.LOG_LOCAL0, nil
	case "LOCAL1":
		return syslog.LOG_LOCAL1, nil
	case "LOCAL2":
		return syslog.LOG_LOCAL2, nil
	case "LOCAL3":
		return syslog.LOG_LOCAL3, nil
	case "LOCAL4":
		return syslog.LOG_LOCAL4, nil
	case "LOCAL5":
		return syslog.LOG_LOCAL5, nil
	case "LOCAL6":
		return syslog.LOG_LOCAL6, nil
	case "LOCAL7":
		return syslog.LOG_LOCAL7, nil
	default:
		return 0, fmt.Errorf("invalid syslog priority: %s", facility)
	}
}

type Syslog struct {
	stopProcess        chan bool
	doneProcess        chan bool
	stopRun            chan bool
	doneRun            chan bool
	inputChan          chan dnsutils.DNSMessage
	outputChan         chan dnsutils.DNSMessage
	config             *dnsutils.Config
	configChan         chan *dnsutils.Config
	logger             *logger.Logger
	severity           syslog.Priority
	facility           syslog.Priority
	syslogWriter       *syslog.Writer
	syslogReady        bool
	transportReady     chan bool
	transportReconnect chan bool
	textFormat         []string
	name               string
}

func NewSyslog(config *dnsutils.Config, console *logger.Logger, name string) *Syslog {
	console.Info("[%s] logger=syslog - enabled", name)
	s := &Syslog{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		inputChan:          make(chan dnsutils.DNSMessage, config.Loggers.Syslog.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DNSMessage, config.Loggers.Syslog.ChannelBufferSize),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             console,
		config:             config,
		configChan:         make(chan *dnsutils.Config),
		name:               name,
	}
	s.ReadConfig()
	return s
}

func (s *Syslog) GetName() string { return s.name }

func (s *Syslog) SetLoggers(loggers []dnsutils.Worker) {}

func (s *Syslog) ReadConfig() {
	if !dnsutils.IsValidTLS(s.config.Loggers.Syslog.TLSMinVersion) {
		s.logger.Fatal("logger=syslog - invalid tls min version")
	}

	if !dnsutils.IsValidMode(s.config.Loggers.Syslog.Mode) {
		s.logger.Fatal("logger=syslog - invalid mode text or json expected")
	}
	severity, err := GetPriority(s.config.Loggers.Syslog.Severity)
	if err != nil {
		s.logger.Fatal("logger=syslog - invalid severity")
	}
	s.severity = severity

	facility, err := GetPriority(s.config.Loggers.Syslog.Facility)
	if err != nil {
		s.logger.Fatal("logger=syslog - invalid facility")
	}
	s.facility = facility

	if len(s.config.Loggers.Syslog.TextFormat) > 0 {
		s.textFormat = strings.Fields(s.config.Loggers.Syslog.TextFormat)
	} else {
		s.textFormat = strings.Fields(s.config.Global.TextFormat)
	}
}

func (s *Syslog) ReloadConfig(config *dnsutils.Config) {
	s.LogInfo("reload configuration!")
	s.configChan <- config
}

func (s *Syslog) Channel() chan dnsutils.DNSMessage {
	return s.inputChan
}

func (s *Syslog) LogInfo(msg string, v ...interface{}) {
	s.logger.Info("["+s.name+"] logger=syslog - "+msg, v...)
}

func (s *Syslog) LogError(msg string, v ...interface{}) {
	s.logger.Error("["+s.name+"] logger=syslog - "+msg, v...)
}

func (s *Syslog) Stop() {
	s.LogInfo("stopping to run...")
	s.stopRun <- true
	<-s.doneRun

	s.LogInfo("stopping to process...")
	s.stopProcess <- true
	<-s.doneProcess
}

func (s *Syslog) ConnectToRemote() {
	for {
		if s.syslogWriter != nil {
			s.syslogWriter.Close()
			s.syslogWriter = nil
		}

		var logWriter *syslog.Writer
		var tlsConfig *tls.Config
		var err error

		switch s.config.Loggers.Syslog.Transport {
		case "local":
			s.LogInfo("connecting to local syslog...")
			logWriter, err = syslog.New(s.facility|s.severity, "")
		case dnsutils.SocketUnix, dnsutils.SocketUDP, dnsutils.SocketTCP:
			s.LogInfo("connecting to %s://%s ...",
				s.config.Loggers.Syslog.Transport,
				s.config.Loggers.Syslog.RemoteAddress)
			logWriter, err = syslog.Dial(s.config.Loggers.Syslog.Transport,
				s.config.Loggers.Syslog.RemoteAddress, s.facility|s.severity,
				s.config.Loggers.Syslog.Tag)
		case dnsutils.SocketTLS:
			s.LogInfo("connecting to %s://%s ...",
				s.config.Loggers.Syslog.Transport,
				s.config.Loggers.Syslog.RemoteAddress)

			tlsOptions := dnsutils.TLSOptions{
				InsecureSkipVerify: s.config.Loggers.Syslog.TLSInsecure,
				MinVersion:         s.config.Loggers.Syslog.TLSMinVersion,
				CAFile:             s.config.Loggers.Syslog.CAFile,
				CertFile:           s.config.Loggers.Syslog.CertFile,
				KeyFile:            s.config.Loggers.Syslog.KeyFile,
			}

			tlsConfig, err = dnsutils.TLSClientConfig(tlsOptions)
			if err == nil {
				logWriter, err = syslog.DialWithTLSConfig(s.config.Loggers.Syslog.Transport,
					s.config.Loggers.Syslog.RemoteAddress, s.facility|s.severity,
					s.config.Loggers.Syslog.Tag,
					tlsConfig)
			}
		default:
			s.logger.Fatal("invalid syslog transport: ", s.config.Loggers.Syslog.Transport)
		}

		// something is wrong during connection ?
		if err != nil {
			s.LogError("%s", err)
			s.LogInfo("retry to connect in %d seconds", s.config.Loggers.Syslog.RetryInterval)
			time.Sleep(time.Duration(s.config.Loggers.Syslog.RetryInterval) * time.Second)
			continue
		}

		s.syslogWriter = logWriter

		// set syslog format
		switch strings.ToLower(s.config.Loggers.Syslog.Formatter) {
		case "unix":
			s.syslogWriter.SetFormatter(syslog.UnixFormatter)
		case "rfc3164":
			s.syslogWriter.SetFormatter(syslog.RFC3164Formatter)
		case "rfc5424", "":
			s.syslogWriter.SetFormatter(syslog.RFC5424Formatter)
		}

		// set syslog framer
		switch strings.ToLower(s.config.Loggers.Syslog.Framer) {
		case "none", "":
			s.syslogWriter.SetFramer(syslog.DefaultFramer)
		case "rfc5425":
			s.syslogWriter.SetFramer(syslog.RFC5425MessageLengthFramer)
		}

		// custom hostname
		if len(s.config.Loggers.Syslog.Hostname) > 0 {
			s.syslogWriter.SetHostname(s.config.Loggers.Syslog.Hostname)
		}
		// custom program name
		if len(s.config.Loggers.Syslog.AppName) > 0 {
			s.syslogWriter.SetProgram(s.config.Loggers.Syslog.AppName)
		}

		// notify process that the transport is ready
		// block the loop until a reconnect is needed
		s.transportReady <- true
		s.transportReconnect <- true
	}
}

func (s *Syslog) Run() {
	s.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, s.outputChan)
	subprocessors := transformers.NewTransforms(&s.config.OutgoingTransformers, s.logger, s.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go s.Process()

	// init remote conn
	go s.ConnectToRemote()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-s.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			s.doneRun <- true
			break RUN_LOOP

		// new config provided?
		case cfg, opened := <-s.configChan:
			if !opened {
				return
			}
			s.config = cfg
			s.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-s.inputChan:
			if !opened {
				s.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// send to output channel
			s.outputChan <- dm
		}
	}
	s.LogInfo("run terminated")
}

func (s *Syslog) Process() {
	var err error
	buffer := new(bytes.Buffer)

	s.LogInfo("processing dns messages...")
PROCESS_LOOP:
	for {
		select {
		case <-s.stopProcess:
			// close connection
			if s.syslogWriter != nil {
				s.syslogWriter.Close()
			}
			s.doneProcess <- true
			break PROCESS_LOOP

		case <-s.transportReady:
			s.LogInfo("syslog transport is ready")
			s.syslogReady = true

		// incoming dns message to process
		case dm, opened := <-s.outputChan:
			if !opened {
				s.LogInfo("output channel closed!")
				return
			}

			// discar dns message if the connection is not ready
			if !s.syslogReady {
				continue
			}

			switch s.config.Loggers.Syslog.Mode {
			case dnsutils.ModeText:
				_, err = s.syslogWriter.Write(dm.Bytes(s.textFormat,
					s.config.Global.TextFormatDelimiter,
					s.config.Global.TextFormatBoundary))

			case dnsutils.ModeJSON:
				json.NewEncoder(buffer).Encode(dm)
				_, err = s.syslogWriter.Write(buffer.Bytes())
				buffer.Reset()

			case dnsutils.ModeFlatJSON:
				flat, errflat := dm.Flatten()
				if errflat != nil {
					s.LogError("flattening DNS message failed: %e", err)
					continue
				}
				json.NewEncoder(buffer).Encode(flat)
				_, err = s.syslogWriter.Write(buffer.Bytes())
				buffer.Reset()
			}

			if err != nil {
				s.LogError("write error %s", err)
				s.syslogReady = false
				s.syslogWriter.Close()
				<-s.transportReconnect
			}
		}
	}
	s.LogInfo("processing terminated")
}
