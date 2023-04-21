package loggers

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type RedisPub struct {
	done               chan bool
	channel            chan dnsutils.DnsMessage
	config             *dnsutils.Config
	logger             *logger.Logger
	exit               chan bool
	textFormat         []string
	name               string
	transportWriter    *bufio.Writer
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	writerReady        bool
}

func NewRedisPub(config *dnsutils.Config, logger *logger.Logger, name string) *RedisPub {
	logger.Info("[%s] logger to redispub - enabled", name)
	s := &RedisPub{
		done:               make(chan bool),
		exit:               make(chan bool),
		channel:            make(chan dnsutils.DnsMessage, 512),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             logger,
		config:             config,
		name:               name,
	}

	s.ReadConfig()

	return s
}

func (c *RedisPub) GetName() string { return c.name }

func (c *RedisPub) SetLoggers(loggers []dnsutils.Worker) {}

func (o *RedisPub) ReadConfig() {

	if o.config.Loggers.RedisPub.TlsSupport && !dnsutils.IsValidTLS(o.config.Loggers.RedisPub.TlsMinVersion) {
		o.logger.Fatal("logger to redispub - invalid tls min version")
	}

	if len(o.config.Loggers.RedisPub.TextFormat) > 0 {
		o.textFormat = strings.Fields(o.config.Loggers.RedisPub.TextFormat)
	} else {
		o.textFormat = strings.Fields(o.config.Global.TextFormat)
	}
}

func (o *RedisPub) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to redispub - "+msg, v...)
}

func (o *RedisPub) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to redispub - "+msg, v...)
}

func (o *RedisPub) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *RedisPub) Stop() {
	o.LogInfo("stopping...")

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *RedisPub) Disconnect() {
	if o.transportConn != nil {
		o.LogInfo("closing redispub connection")
		o.transportConn.Close()
	}
}

func (o *RedisPub) ConnectToRemote() {
	// prepare the address
	var address string
	if len(o.config.Loggers.RedisPub.SockPath) > 0 {
		address = o.config.Loggers.RedisPub.SockPath
	} else {
		address = o.config.Loggers.RedisPub.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.RedisPub.RemotePort)
	}
	connTimeout := time.Duration(o.config.Loggers.RedisPub.ConnectTimeout) * time.Second

	for {
		if o.transportConn != nil {
			o.transportConn.Close()
			o.transportConn = nil
		}

		// make the connection
		o.LogInfo("connecting to %s", address)
		var conn net.Conn
		var err error
		if o.config.Loggers.RedisPub.TlsSupport {
			tlsConfig := &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			}
			tlsConfig.InsecureSkipVerify = o.config.Loggers.RedisPub.TlsInsecure
			tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.RedisPub.TlsMinVersion]

			dialer := &net.Dialer{Timeout: connTimeout}
			conn, err = tls.DialWithDialer(dialer, o.config.Loggers.RedisPub.Transport, address, tlsConfig)
		} else {
			conn, err = net.DialTimeout(o.config.Loggers.RedisPub.Transport, address, connTimeout)
		}

		// something is wrong during connection ?
		if err != nil {
			o.LogError("%s", err)
			o.LogInfo("retry to connect in %d seconds", o.config.Loggers.RedisPub.RetryInterval)
			time.Sleep(time.Duration(o.config.Loggers.RedisPub.RetryInterval) * time.Second)
			continue
		}

		o.transportConn = conn

		// block until framestream is ready
		o.transportReady <- true

		// block until an error occured, need to reconnect
		o.transportReconnect <- true
	}
}

func (o *RedisPub) FlushBuffer(buf *[]dnsutils.DnsMessage) {
	for _, dm := range *buf {

		cmd := "PUBLISH " + strconv.Quote(o.config.Loggers.RedisPub.RedisChannel) + " "
		o.transportWriter.WriteString(cmd)

		if o.config.Loggers.RedisPub.Mode == dnsutils.MODE_TEXT {
			o.transportWriter.WriteString(strconv.Quote(dm.String(o.textFormat, o.config.Global.TextFormatDelimiter, o.config.Global.TextFormatBoundary)))
			o.transportWriter.WriteString(o.config.Loggers.RedisPub.PayloadDelimiter)
		}

		// Create escaping buffer
		buf := new(bytes.Buffer)
		// Create a new encoder that writes to the buffer
		encoder := json.NewEncoder(buf)

		if o.config.Loggers.RedisPub.Mode == dnsutils.MODE_JSON {
			encoder.Encode(dm)
			escapedData := strconv.Quote(buf.String())
			o.transportWriter.WriteString(escapedData)
			o.transportWriter.WriteString(o.config.Loggers.RedisPub.PayloadDelimiter)
		}

		if o.config.Loggers.RedisPub.Mode == dnsutils.MODE_FLATJSON {
			flat, err := dm.Flatten()
			if err != nil {
				o.LogError("flattening DNS message failed: %e", err)
				continue
			}
			encoder.Encode(flat)
			escapedData := strconv.Quote(buf.String())
			o.transportWriter.WriteString(escapedData)
			o.transportWriter.WriteString(o.config.Loggers.RedisPub.PayloadDelimiter)
		}

		// flush the transport buffer
		err := o.transportWriter.Flush()
		if err != nil {
			o.LogError("send frame error", err.Error())
			o.writerReady = false
			<-o.transportReconnect
			break
		}
	}

	// reset buffer
	*buf = nil
}

func (o *RedisPub) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.channel)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel)

	// init buffer
	bufferDm := []dnsutils.DnsMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(o.config.Loggers.RedisPub.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// init remote conn
	go o.ConnectToRemote()

LOOP:
	for {
		select {
		case <-o.exit:
			o.logger.Info("closing loop...")
			break LOOP

		case <-o.transportReady:
			o.LogInfo("transport connected with success")
			o.transportWriter = bufio.NewWriter(o.transportConn)
			o.writerReady = true

		case dm := <-o.channel:
			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !o.writerReady {
				continue
			}

			// apply tranforms
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= o.config.Loggers.RedisPub.BufferSize {
				o.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !o.writerReady {
				fmt.Println("buffer cleared!")
				bufferDm = nil
				continue
			}

			if len(bufferDm) > 0 {
				o.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)

		}
	}

	o.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// closing remote connection if exist
	o.Disconnect()

	o.done <- true
}
