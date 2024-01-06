package loggers

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type RedisPub struct {
	stopProcess        chan bool
	doneProcess        chan bool
	stopRun            chan bool
	doneRun            chan bool
	stopRead           chan bool
	doneRead           chan bool
	inputChan          chan dnsutils.DNSMessage
	outputChan         chan dnsutils.DNSMessage
	config             *pkgconfig.Config
	configChan         chan *pkgconfig.Config
	logger             *logger.Logger
	textFormat         []string
	name               string
	transport          string
	transportWriter    *bufio.Writer
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	writerReady        bool
	RoutingHandler     pkgutils.RoutingHandler
}

func NewRedisPub(config *pkgconfig.Config, logger *logger.Logger, name string) *RedisPub {
	logger.Info("[%s] logger=redispub - enabled", name)
	s := &RedisPub{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		stopRead:           make(chan bool),
		doneRead:           make(chan bool),
		inputChan:          make(chan dnsutils.DNSMessage, config.Loggers.RedisPub.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DNSMessage, config.Loggers.RedisPub.ChannelBufferSize),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             logger,
		config:             config,
		configChan:         make(chan *pkgconfig.Config),
		name:               name,
		RoutingHandler:     pkgutils.NewRoutingHandler(config, logger, name),
	}

	s.ReadConfig()

	return s
}

func (c *RedisPub) GetName() string { return c.name }

func (c *RedisPub) AddDroppedRoute(wrk pkgutils.Worker) {
	c.RoutingHandler.AddDroppedRoute(wrk)
}

func (c *RedisPub) AddDefaultRoute(wrk pkgutils.Worker) {
	c.RoutingHandler.AddDefaultRoute(wrk)
}

func (c *RedisPub) SetLoggers(loggers []pkgutils.Worker) {}

func (c *RedisPub) ReadConfig() {

	c.transport = c.config.Loggers.RedisPub.Transport

	// begin backward compatibility
	if c.config.Loggers.RedisPub.TLSSupport {
		c.transport = netlib.SocketTLS
	}
	if len(c.config.Loggers.RedisPub.SockPath) > 0 {
		c.transport = netlib.SocketUnix
	}
	// end

	if len(c.config.Loggers.RedisPub.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.RedisPub.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}
}

func (c *RedisPub) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *RedisPub) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=redispub - "+msg, v...)
}

func (c *RedisPub) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=redispub - "+msg, v...)
}

func (c *RedisPub) GetInputChannel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *RedisPub) Stop() {
	c.LogInfo("stopping routing handler...")
	c.RoutingHandler.Stop()

	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to receive...")
	c.stopRead <- true
	<-c.doneRead

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess
}

func (c *RedisPub) Disconnect() {
	if c.transportConn != nil {
		c.LogInfo("closing redispub connection")
		c.transportConn.Close()
	}
}

func (c *RedisPub) ReadFromConnection() {
	buffer := make([]byte, 4096)

	go func() {
		for {
			_, err := c.transportConn.Read(buffer)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					c.LogInfo("read from connection terminated")
					break
				}
				c.LogError("Error on reading: %s", err.Error())
			}
			// We just discard the data
		}
	}()

	// block goroutine until receive true event in stopRead channel
	<-c.stopRead
	c.doneRead <- true

	c.LogInfo("read goroutine terminated")
}

func (c *RedisPub) ConnectToRemote() {
	for {
		if c.transportConn != nil {
			c.transportConn.Close()
			c.transportConn = nil
		}

		address := c.config.Loggers.RedisPub.RemoteAddress + ":" + strconv.Itoa(c.config.Loggers.RedisPub.RemotePort)
		connTimeout := time.Duration(c.config.Loggers.RedisPub.ConnectTimeout) * time.Second

		var conn net.Conn
		var err error

		switch c.transport {
		case netlib.SocketUnix:
			address = c.config.Loggers.RedisPub.RemoteAddress
			if len(c.config.Loggers.RedisPub.SockPath) > 0 {
				address = c.config.Loggers.RedisPub.SockPath
			}
			c.LogInfo("connecting to %s://%s", c.transport, address)
			conn, err = net.DialTimeout(c.transport, address, connTimeout)

		case netlib.SocketTCP:
			c.LogInfo("connecting to %s://%s", c.transport, address)
			conn, err = net.DialTimeout(c.transport, address, connTimeout)

		case netlib.SocketTLS:
			c.LogInfo("connecting to %s://%s", c.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := pkgconfig.TLSOptions{
				InsecureSkipVerify: c.config.Loggers.RedisPub.TLSInsecure,
				MinVersion:         c.config.Loggers.RedisPub.TLSMinVersion,
				CAFile:             c.config.Loggers.RedisPub.CAFile,
				CertFile:           c.config.Loggers.RedisPub.CertFile,
				KeyFile:            c.config.Loggers.RedisPub.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netlib.SocketTCP, address, tlsConfig)
			}

		default:
			c.logger.Fatal("logger=redispub - invalid transport:", c.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			c.LogError("%s", err)
			c.LogInfo("retry to connect in %d seconds", c.config.Loggers.RedisPub.RetryInterval)
			time.Sleep(time.Duration(c.config.Loggers.RedisPub.RetryInterval) * time.Second)
			continue
		}

		c.transportConn = conn

		// block until framestream is ready
		c.transportReady <- true

		// block until an error occurred, need to reconnect
		c.transportReconnect <- true
	}
}

func (c *RedisPub) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	// create escaping buffer
	escapeBuffer := new(bytes.Buffer)
	// create a new encoder that writes to the buffer
	encoder := json.NewEncoder(escapeBuffer)

	for _, dm := range *buf {
		escapeBuffer.Reset()

		cmd := "PUBLISH " + strconv.Quote(c.config.Loggers.RedisPub.RedisChannel) + " "
		c.transportWriter.WriteString(cmd)

		if c.config.Loggers.RedisPub.Mode == pkgconfig.ModeText {
			c.transportWriter.WriteString(strconv.Quote(dm.String(c.textFormat, c.config.Global.TextFormatDelimiter, c.config.Global.TextFormatBoundary)))
			c.transportWriter.WriteString(c.config.Loggers.RedisPub.PayloadDelimiter)
		}

		if c.config.Loggers.RedisPub.Mode == pkgconfig.ModeJSON {
			encoder.Encode(dm)
			c.transportWriter.WriteString(strconv.Quote(escapeBuffer.String()))
			c.transportWriter.WriteString(c.config.Loggers.RedisPub.PayloadDelimiter)
		}

		if c.config.Loggers.RedisPub.Mode == pkgconfig.ModeFlatJSON {
			flat, err := dm.Flatten()
			if err != nil {
				c.LogError("flattening DNS message failed: %e", err)
				continue
			}
			encoder.Encode(flat)
			c.transportWriter.WriteString(strconv.Quote(escapeBuffer.String()))
			c.transportWriter.WriteString(c.config.Loggers.RedisPub.PayloadDelimiter)
		}

		// flush the transport buffer
		err := c.transportWriter.Flush()
		if err != nil {
			c.LogError("send frame error", err.Error())
			c.writerReady = false
			<-c.transportReconnect
			break
		}
	}

	// reset buffer
	*buf = nil
}

func (c *RedisPub) Run() {
	c.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := c.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := c.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, c.outputChan)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go c.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-c.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			c.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-c.configChan:
			if !opened {
				return
			}
			c.config = cfg
			c.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-c.inputChan:
			if !opened {
				c.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				c.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			c.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			c.outputChan <- dm
		}
	}
	c.LogInfo("run terminated")
}

func (c *RedisPub) Process() {
	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(c.config.Loggers.RedisPub.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// init remote conn
	go c.ConnectToRemote()

	c.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-c.stopProcess:
			// closing remote connection if exist
			c.Disconnect()
			c.doneProcess <- true
			break PROCESS_LOOP

		case <-c.transportReady:
			c.LogInfo("transport connected with success")
			c.transportWriter = bufio.NewWriter(c.transportConn)
			c.writerReady = true
			// read from the connection until we stop
			go c.ReadFromConnection()

		// incoming dns message to process
		case dm, opened := <-c.outputChan:
			if !opened {
				c.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !c.writerReady {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= c.config.Loggers.RedisPub.BufferSize {
				c.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !c.writerReady {
				c.LogInfo("Buffer cleared!")
				bufferDm = nil
				continue
			}

			if len(bufferDm) > 0 {
				c.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)

		}
	}
	c.LogInfo("processing terminated")
}
