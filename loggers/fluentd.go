package loggers

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/vmihailenco/msgpack"
)

type FluentdClient struct {
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
	transport          string
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	writerReady        bool
	name               string
}

func NewFluentdClient(config *pkgconfig.Config, logger *logger.Logger, name string) *FluentdClient {
	logger.Info("[%s] logger=fluentd - enabled", name)
	s := &FluentdClient{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		stopRead:           make(chan bool),
		doneRead:           make(chan bool),
		inputChan:          make(chan dnsutils.DNSMessage, config.Loggers.Fluentd.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DNSMessage, config.Loggers.Fluentd.ChannelBufferSize),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             logger,
		config:             config,
		configChan:         make(chan *pkgconfig.Config),
		name:               name,
	}

	s.ReadConfig()

	return s
}

func (c *FluentdClient) GetName() string { return c.name }

func (c *FluentdClient) SetLoggers(loggers []dnsutils.Worker) {}

func (c *FluentdClient) ReadConfig() {
	c.transport = c.config.Loggers.Fluentd.Transport

	// begin backward compatibility
	if c.config.Loggers.Fluentd.TLSSupport {
		c.transport = pkgconfig.SocketTLS
	}
	if len(c.config.Loggers.Fluentd.SockPath) > 0 {
		c.transport = pkgconfig.SocketUnix
	}
	// end
}

func (c *FluentdClient) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *FluentdClient) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=fluentd - "+msg, v...)
}

func (c *FluentdClient) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=fluentd - "+msg, v...)
}

func (c *FluentdClient) Channel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *FluentdClient) Stop() {
	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to read...")
	c.stopRead <- true
	<-c.doneRead

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess
}

func (c *FluentdClient) Disconnect() {
	if c.transportConn != nil {
		c.LogInfo("closing tcp connection")
		c.transportConn.Close()
	}
}

func (c *FluentdClient) ReadFromConnection() {
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

func (c *FluentdClient) ConnectToRemote() {
	for {
		if c.transportConn != nil {
			c.transportConn.Close()
			c.transportConn = nil
		}

		address := c.config.Loggers.Fluentd.RemoteAddress + ":" + strconv.Itoa(c.config.Loggers.Fluentd.RemotePort)
		connTimeout := time.Duration(c.config.Loggers.Fluentd.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch c.transport {
		case pkgconfig.SocketUnix:
			address = c.config.Loggers.Fluentd.RemoteAddress
			if len(c.config.Loggers.Fluentd.SockPath) > 0 {
				address = c.config.Loggers.Fluentd.SockPath
			}
			c.LogInfo("connecting to %s://%s", c.transport, address)
			conn, err = net.DialTimeout(c.transport, address, connTimeout)

		case pkgconfig.SocketTCP:
			c.LogInfo("connecting to %s://%s", c.transport, address)
			conn, err = net.DialTimeout(c.transport, address, connTimeout)

		case pkgconfig.SocketTLS:
			c.LogInfo("connecting to %s://%s", c.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := pkgconfig.TLSOptions{
				InsecureSkipVerify: c.config.Loggers.Fluentd.TLSInsecure,
				MinVersion:         c.config.Loggers.Fluentd.TLSMinVersion,
				CAFile:             c.config.Loggers.Fluentd.CAFile,
				CertFile:           c.config.Loggers.Fluentd.CertFile,
				KeyFile:            c.config.Loggers.Fluentd.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, pkgconfig.SocketTCP, address, tlsConfig)
			}
		default:
			c.logger.Fatal("logger=fluent - invalid transport:", c.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			c.LogError("connect error: %s", err)
			c.LogInfo("retry to connect in %d seconds", c.config.Loggers.Fluentd.RetryInterval)
			time.Sleep(time.Duration(c.config.Loggers.Fluentd.RetryInterval) * time.Second)
			continue
		}

		c.transportConn = conn

		// block until framestream is ready
		c.transportReady <- true

		// block until an error occured, need to reconnect
		c.transportReconnect <- true
	}
}

func (c *FluentdClient) FlushBuffer(buf *[]dnsutils.DNSMessage) {

	tag, _ := msgpack.Marshal(c.config.Loggers.Fluentd.Tag)

	for _, dm := range *buf {
		// prepare event
		tm, _ := msgpack.Marshal(dm.DNSTap.TimeSec)
		record, err := msgpack.Marshal(dm)
		if err != nil {
			c.LogError("msgpack error:", err.Error())
			continue
		}

		// Message ::= [ Tag, Time, Record, Option? ]
		encoded := []byte{}
		// array, size 3
		encoded = append(encoded, 0x93)
		// append tag, time and record
		encoded = append(encoded, tag...)
		encoded = append(encoded, tm...)
		encoded = append(encoded, record...)

		// write event message
		_, err = c.transportConn.Write(encoded)

		// flusth the buffer
		if err != nil {
			c.LogError("send transport error", err.Error())
			c.writerReady = false
			<-c.transportReconnect
			break
		}
	}
}

func (c *FluentdClient) Run() {
	c.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, c.outputChan)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go c.Process()

	// init remote conn
	go c.ConnectToRemote()

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
				continue
			}

			// send to output channel
			c.outputChan <- dm
		}
	}
	c.LogInfo("run terminated")
}

func (c *FluentdClient) Process() {
	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(c.config.Loggers.Fluentd.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	c.LogInfo("ready to process")

PROCESS_LOOP:
	for {
		select {
		case <-c.stopProcess:
			c.doneProcess <- true
			break PROCESS_LOOP

		case <-c.transportReady:
			c.LogInfo("connected")
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
			if len(bufferDm) >= c.config.Loggers.Fluentd.BufferSize {
				c.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !c.writerReady {
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
