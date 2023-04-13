package loggers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"

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
	done       chan bool
	channel    chan dnsutils.DnsMessage
	config     *dnsutils.Config
	logger     *logger.Logger
	severity   syslog.Priority
	facility   syslog.Priority
	syslogConn *syslog.Writer
	textFormat []string
	name       string
}

func NewSyslog(config *dnsutils.Config, console *logger.Logger, name string) *Syslog {
	console.Info("[%s] logger syslog - enabled", name)
	o := &Syslog{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  console,
		config:  config,
		name:    name,
	}
	o.ReadConfig()
	return o
}

func (c *Syslog) GetName() string { return c.name }

func (c *Syslog) SetLoggers(loggers []dnsutils.Worker) {}

func (c *Syslog) ReadConfig() {
	if !dnsutils.IsValidTLS(c.config.Loggers.Syslog.TlsMinVersion) {
		c.logger.Fatal("logger syslog - invalid tls min version")
	}

	if !dnsutils.IsValidMode(c.config.Loggers.Syslog.Mode) {
		c.logger.Fatal("logger syslog - invalid mode text or json expected")
	}
	severity, err := GetPriority(c.config.Loggers.Syslog.Severity)
	if err != nil {
		c.logger.Fatal("logger syslog - invalid severity")
	}
	c.severity = severity

	facility, err := GetPriority(c.config.Loggers.Syslog.Facility)
	if err != nil {
		c.logger.Fatal("logger syslog - invalid facility")
	}
	c.facility = facility

	if len(c.config.Loggers.Syslog.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.Syslog.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}
}

func (o *Syslog) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *Syslog) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to syslog - "+msg, v...)
}

func (o *Syslog) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to syslog - "+msg, v...)
}

func (o *Syslog) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// close connection
	o.LogInfo("closing connection")
	o.syslogConn.Close()

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *Syslog) Run() {
	o.LogInfo("running in background...")

	// prepare enabled transformers
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.channel)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel)

	var syslogconn *syslog.Writer
	var err error
	buffer := new(bytes.Buffer)

	if o.config.Loggers.Syslog.Transport == "local" {
		syslogconn, err = syslog.New(o.facility|o.severity, "")
		if err != nil {
			o.logger.Fatal("failed to connect to the local syslog daemon:", err)
		}
	} else {
		if o.config.Loggers.Syslog.TlsSupport {
			tlsConfig := &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			}
			tlsConfig.InsecureSkipVerify = o.config.Loggers.Syslog.TlsInsecure
			tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.Syslog.TlsMinVersion]

			syslogconn, err = syslog.DialWithTLSConfig(o.config.Loggers.Syslog.Transport,
				o.config.Loggers.Syslog.RemoteAddress, o.facility|o.severity, "", tlsConfig)
			if err != nil {
				o.logger.Fatal("failed to connect to the remote tls syslog:", err)
			}
		} else {
			syslogconn, err = syslog.Dial(o.config.Loggers.Syslog.Transport,
				o.config.Loggers.Syslog.RemoteAddress, o.facility|o.severity, "")
			if err != nil {
				o.logger.Fatal("failed to connect to the remote syslog:", err)
			}
		}
	}

	switch strings.ToLower(o.config.Loggers.Syslog.Format) {
	case "rfc3164":
		syslogconn.SetFormatter(syslog.RFC3164Formatter)
	case "rfc5424":
		syslogconn.SetFormatter(syslog.RFC5424Formatter)
	}

	o.syslogConn = syslogconn

	for dm := range o.channel {
		// apply tranforms
		if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
			continue
		}

		switch o.config.Loggers.Syslog.Mode {
		case dnsutils.MODE_TEXT:

			o.syslogConn.Write(dm.Bytes(o.textFormat,
				o.config.Global.TextFormatDelimiter,
				o.config.Global.TextFormatBoundary))

			var delimiter bytes.Buffer
			delimiter.WriteString("\n")
			o.syslogConn.Write(delimiter.Bytes())

		case dnsutils.MODE_JSON:
			json.NewEncoder(buffer).Encode(dm)
			o.syslogConn.Write(buffer.Bytes())
			buffer.Reset()

		case dnsutils.MODE_FLATJSON:
			flat, err := dm.Flatten()
			if err != nil {
				o.LogError("flattening DNS message failed: %e", err)
			}
			json.NewEncoder(buffer).Encode(flat)
			o.syslogConn.Write(buffer.Bytes())
			buffer.Reset()
		}
	}

	o.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	o.done <- true
}
