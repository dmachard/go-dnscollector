package loggers

import (
	"bufio"
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

type TCPClient struct {
	stopProcess, doneProcess           chan bool
	stopRun, doneRun                   chan bool
	stopRead, doneRead                 chan bool
	inputChan, outputChan              chan dnsutils.DNSMessage
	config                             *pkgconfig.Config
	configChan                         chan *pkgconfig.Config
	logger                             *logger.Logger
	textFormat                         []string
	name                               string
	transport                          string
	transportWriter                    *bufio.Writer
	transportConn                      net.Conn
	transportReady, transportReconnect chan bool
	writerReady                        bool
	RoutingHandler                     pkgutils.RoutingHandler
}

func NewTCPClient(config *pkgconfig.Config, logger *logger.Logger, name string) *TCPClient {
	logger.Info(pkgutils.PrefixLogLogger+"[%s] tcpclient - enabled", name)
	s := &TCPClient{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		stopRead:           make(chan bool),
		doneRead:           make(chan bool),
		inputChan:          make(chan dnsutils.DNSMessage, config.Loggers.TCPClient.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DNSMessage, config.Loggers.TCPClient.ChannelBufferSize),
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

func (c *TCPClient) GetName() string { return c.name }

func (c *TCPClient) AddDroppedRoute(wrk pkgutils.Worker) {
	c.RoutingHandler.AddDroppedRoute(wrk)
}

func (c *TCPClient) AddDefaultRoute(wrk pkgutils.Worker) {
	c.RoutingHandler.AddDefaultRoute(wrk)
}

func (c *TCPClient) SetLoggers(loggers []pkgutils.Worker) {}

func (c *TCPClient) ReadConfig() {
	c.transport = c.config.Loggers.TCPClient.Transport

	// begin backward compatibility
	if c.config.Loggers.TCPClient.TLSSupport {
		c.transport = netlib.SocketTLS
	}
	if len(c.config.Loggers.TCPClient.SockPath) > 0 {
		c.transport = netlib.SocketUnix
	}
	// end

	if len(c.config.Loggers.TCPClient.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.TCPClient.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}
}

func (c *TCPClient) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *TCPClient) LogInfo(msg string, v ...interface{}) {
	c.logger.Info(pkgutils.PrefixLogLogger+"["+c.name+"] tcpclient - "+msg, v...)
}

func (c *TCPClient) LogError(msg string, v ...interface{}) {
	c.logger.Error(pkgutils.PrefixLogLogger+"["+c.name+"] tcpclient - "+msg, v...)
}

func (c *TCPClient) GetInputChannel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *TCPClient) Stop() {
	c.LogInfo("stopping logger...")
	c.RoutingHandler.Stop()

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

func (c *TCPClient) Disconnect() {
	if c.transportConn != nil {
		c.LogInfo("closing tcp connection")
		c.transportConn.Close()
	}
}

func (c *TCPClient) ReadFromConnection() {
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

func (c *TCPClient) ConnectToRemote() {
	for {
		if c.transportConn != nil {
			c.transportConn.Close()
			c.transportConn = nil
		}

		address := c.config.Loggers.TCPClient.RemoteAddress + ":" + strconv.Itoa(c.config.Loggers.TCPClient.RemotePort)
		connTimeout := time.Duration(c.config.Loggers.TCPClient.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch c.transport {
		case netlib.SocketUnix:
			address = c.config.Loggers.TCPClient.RemoteAddress
			if len(c.config.Loggers.TCPClient.SockPath) > 0 {
				address = c.config.Loggers.TCPClient.SockPath
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
				InsecureSkipVerify: c.config.Loggers.TCPClient.TLSInsecure,
				MinVersion:         c.config.Loggers.TCPClient.TLSMinVersion,
				CAFile:             c.config.Loggers.TCPClient.CAFile,
				CertFile:           c.config.Loggers.TCPClient.CertFile,
				KeyFile:            c.config.Loggers.TCPClient.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netlib.SocketTCP, address, tlsConfig)
			}
		default:
			c.logger.Fatal("logger=tcpclient - invalid transport:", c.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			c.LogError("%s", err)
			c.LogInfo("retry to connect in %d seconds", c.config.Loggers.TCPClient.RetryInterval)
			time.Sleep(time.Duration(c.config.Loggers.TCPClient.RetryInterval) * time.Second)
			continue
		}

		c.transportConn = conn

		// block until framestream is ready
		c.transportReady <- true

		// block until an error occurred, need to reconnect
		c.transportReconnect <- true
	}
}

func (c *TCPClient) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	for _, dm := range *buf {
		if c.config.Loggers.TCPClient.Mode == pkgconfig.ModeText {
			c.transportWriter.Write(dm.Bytes(c.textFormat,
				c.config.Global.TextFormatDelimiter,
				c.config.Global.TextFormatBoundary))
			c.transportWriter.WriteString(c.config.Loggers.TCPClient.PayloadDelimiter)
		}

		if c.config.Loggers.TCPClient.Mode == pkgconfig.ModeJSON {
			json.NewEncoder(c.transportWriter).Encode(dm)
			c.transportWriter.WriteString(c.config.Loggers.TCPClient.PayloadDelimiter)
		}

		if c.config.Loggers.TCPClient.Mode == pkgconfig.ModeFlatJSON {
			flat, err := dm.Flatten()
			if err != nil {
				c.LogError("flattening DNS message failed: %e", err)
				continue
			}
			json.NewEncoder(c.transportWriter).Encode(flat)
			c.transportWriter.WriteString(c.config.Loggers.TCPClient.PayloadDelimiter)
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

func (c *TCPClient) Run() {
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

func (c *TCPClient) Process() {
	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(c.config.Loggers.TCPClient.FlushInterval) * time.Second
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
			if len(bufferDm) >= c.config.Loggers.TCPClient.BufferSize {
				c.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !c.writerReady {
				bufferDm = nil
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
