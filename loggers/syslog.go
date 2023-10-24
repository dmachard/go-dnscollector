package loggers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"strings"

	syslog "github.com/RackSec/srslog"

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
	inputChan          chan dnsutils.DnsMessage
	outputChan         chan dnsutils.DnsMessage
	config             *dnsutils.Config
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
	o := &Syslog{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		inputChan:          make(chan dnsutils.DnsMessage, config.Loggers.Syslog.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DnsMessage, config.Loggers.Syslog.ChannelBufferSize),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             console,
		config:             config,
		name:               name,
	}
	o.ReadConfig()
	return o
}

func (c *Syslog) GetName() string { return c.name }

func (c *Syslog) SetLoggers(loggers []dnsutils.Worker) {}

func (c *Syslog) ReadConfig() {
	if !dnsutils.IsValidTLS(c.config.Loggers.Syslog.TlsMinVersion) {
		c.logger.Fatal("logger=syslog - invalid tls min version")
	}

	if !dnsutils.IsValidMode(c.config.Loggers.Syslog.Mode) {
		c.logger.Fatal("logger=syslog - invalid mode text or json expected")
	}
	severity, err := GetPriority(c.config.Loggers.Syslog.Severity)
	if err != nil {
		c.logger.Fatal("logger=syslog - invalid severity")
	}
	c.severity = severity

	facility, err := GetPriority(c.config.Loggers.Syslog.Facility)
	if err != nil {
		c.logger.Fatal("logger=syslog - invalid facility")
	}
	c.facility = facility

	if len(c.config.Loggers.Syslog.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.Syslog.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}
}

func (o *Syslog) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload config...")

	// save the new config
	o.config = config

	// read again
	o.ReadConfig()
}

func (o *Syslog) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *Syslog) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger=syslog - "+msg, v...)
}

func (o *Syslog) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger=syslog - "+msg, v...)
}

func (o *Syslog) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *Syslog) ConnectToRemote() {
	//connTimeout := time.Duration(o.config.Loggers.Dnstap.ConnectTimeout) * time.Second

	for {
		if o.syslogWriter != nil {
			o.syslogWriter.Close()
			o.syslogWriter = nil
		}

		var logWriter *syslog.Writer
		var err error

		switch o.config.Loggers.Syslog.Transport {
		case "local":
			o.LogInfo("connecting to local syslog...")
			logWriter, err = syslog.New(o.facility|o.severity, "")
		case dnsutils.SOCKET_UNIX, dnsutils.SOCKET_UDP, dnsutils.SOCKET_TCP:
			o.LogInfo("connecting to syslog %s://%s ...", o.config.Loggers.Syslog.Transport, o.config.Loggers.Syslog.RemoteAddress)
			logWriter, err = syslog.Dial(o.config.Loggers.Syslog.Transport,
				o.config.Loggers.Syslog.RemoteAddress, o.facility|o.severity,
				o.config.Loggers.Syslog.Tag)
		case dnsutils.SOCKET_TLS:
			o.LogInfo("connecting to syslog %s://%s ...", o.config.Loggers.Syslog.Transport, o.config.Loggers.Syslog.RemoteAddress)
			tlsConfig := &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			}
			tlsConfig.InsecureSkipVerify = o.config.Loggers.Syslog.TlsInsecure
			tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.Syslog.TlsMinVersion]

			logWriter, err = syslog.DialWithTLSConfig(o.config.Loggers.Syslog.Transport,
				o.config.Loggers.Syslog.RemoteAddress, o.facility|o.severity,
				o.config.Loggers.Syslog.Tag,
				tlsConfig)
		default:
			o.logger.Fatal("invalid syslog transport: ", o.config.Loggers.Syslog.Transport)
		}

		// something is wrong during connection ?
		if err != nil {
			o.LogError("%s", err)
			o.LogInfo("retry to connect in %d seconds", o.config.Loggers.Syslog.RetryInterval)
			time.Sleep(time.Duration(o.config.Loggers.Syslog.RetryInterval) * time.Second)
			continue
		}

		o.syslogWriter = logWriter

		switch strings.ToLower(o.config.Loggers.Syslog.Format) {
		case "rfc3164":
			o.syslogWriter.SetFormatter(syslog.RFC3164Formatter)
		case "rfc5424":
			o.syslogWriter.SetFormatter(syslog.RFC5424Formatter)
		case "rfc5425":
			o.syslogWriter.SetFormatter(syslog.RFC5424Formatter)
			o.syslogWriter.SetFramer(syslog.RFC5425MessageLengthFramer)
		}

		// notify process that the transport is ready
		// block the loop until a reconnect is needed
		o.transportReady <- true

		o.transportReconnect <- true
	}
}

func (o *Syslog) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.outputChan)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go o.Process()

	// init remote conn
	go o.ConnectToRemote()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-o.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			o.doneRun <- true
			break RUN_LOOP

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

func (o *Syslog) Process() {
	var err error
	buffer := new(bytes.Buffer)

	o.LogInfo("processing dns messages...")
PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			// close connection
			if o.syslogWriter != nil {
				o.syslogWriter.Close()
			}
			o.doneProcess <- true
			break PROCESS_LOOP

		case <-o.transportReady:
			o.LogInfo("syslog transport is ready")
			o.syslogReady = true

		// incoming dns message to process
		case dm, opened := <-o.outputChan:
			if !opened {
				o.LogInfo("output channel closed!")
				return
			}

			// discar dns message if the connection is not ready
			if !o.syslogReady {
				continue
			}

			switch o.config.Loggers.Syslog.Mode {
			case dnsutils.MODE_TEXT:
				_, err = o.syslogWriter.Write(dm.Bytes(o.textFormat,
					o.config.Global.TextFormatDelimiter,
					o.config.Global.TextFormatBoundary))

			case dnsutils.MODE_JSON:
				json.NewEncoder(buffer).Encode(dm)
				_, err = o.syslogWriter.Write(buffer.Bytes())
				buffer.Reset()

			case dnsutils.MODE_FLATJSON:
				flat, errflat := dm.Flatten()
				if errflat != nil {
					o.LogError("flattening DNS message failed: %e", err)
					continue
				}
				json.NewEncoder(buffer).Encode(flat)
				_, err = o.syslogWriter.Write(buffer.Bytes())
				buffer.Reset()
			}

			if err != nil {
				o.LogError("write error %s", err)
				o.syslogReady = false
				o.syslogWriter.Close()
				<-o.transportReconnect
			}
		}
	}
	o.LogInfo("processing terminated")
}
