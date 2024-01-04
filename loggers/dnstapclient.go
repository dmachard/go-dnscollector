package loggers

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapSender struct {
	stopProcess        chan bool
	doneProcess        chan bool
	stopRun            chan bool
	doneRun            chan bool
	inputChan          chan dnsutils.DNSMessage
	outputChan         chan dnsutils.DNSMessage
	config             *pkgconfig.Config
	configChan         chan *pkgconfig.Config
	logger             *logger.Logger
	fs                 *framestream.Fstrm
	fsReady            bool
	transport          string
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	name               string
	droppedCount       map[string]int
	dropped            chan string
	droppedRoutes      []pkgutils.Worker
	defaultRoutes      []pkgutils.Worker
}

func NewDnstapSender(config *pkgconfig.Config, logger *logger.Logger, name string) *DnstapSender {
	logger.Info("[%s] logger=dnstap - enabled", name)
	s := &DnstapSender{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		inputChan:          make(chan dnsutils.DNSMessage, config.Loggers.DNSTap.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DNSMessage, config.Loggers.DNSTap.ChannelBufferSize),
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

func (c *DnstapSender) GetName() string { return c.name }

func (c *DnstapSender) AddDroppedRoute(wrk pkgutils.Worker) {
	c.droppedRoutes = append(c.droppedRoutes, wrk)
}

func (c *DnstapSender) AddDefaultRoute(wrk pkgutils.Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *DnstapSender) GetDefaultRoutes() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetActiveRoutes(c.defaultRoutes)
}

func (c *DnstapSender) GetDroppedRoutes() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetActiveRoutes(c.droppedRoutes)
}

func (c *DnstapSender) SetLoggers(loggers []pkgutils.Worker) {}

func (c *DnstapSender) ReadConfig() {
	c.transport = c.config.Loggers.DNSTap.Transport

	// begin backward compatibility
	if c.config.Loggers.DNSTap.TLSSupport {
		c.transport = netlib.SocketTLS
	}
	if len(c.config.Loggers.DNSTap.SockPath) > 0 {
		c.transport = netlib.SocketUnix
	}
	// end

	// get hostname or global one
	if c.config.Loggers.DNSTap.ServerID == "" {
		c.config.Loggers.DNSTap.ServerID = c.config.GetServerIdentity()
	}

	if !pkgconfig.IsValidTLS(c.config.Loggers.DNSTap.TLSMinVersion) {
		c.logger.Fatal("logger=dnstap - invalid tls min version")
	}
}

func (c *DnstapSender) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *DnstapSender) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=dnstap - "+msg, v...)
}

func (c *DnstapSender) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=dnstap - "+msg, v...)
}

func (c *DnstapSender) GetInputChannel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *DnstapSender) Stop() {
	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess
}

func (c *DnstapSender) Disconnect() {
	if c.transportConn != nil {
		// reset framestream and ignore errors
		c.LogInfo("closing framestream")
		c.fs.ResetSender()

		// closing tcp
		c.LogInfo("closing tcp connection")
		c.transportConn.Close()
		c.LogInfo("closed")
	}
}

func (c *DnstapSender) ConnectToRemote() {
	for {
		if c.transportConn != nil {
			c.transportConn.Close()
			c.transportConn = nil
		}

		address := net.JoinHostPort(
			c.config.Loggers.DNSTap.RemoteAddress,
			strconv.Itoa(c.config.Loggers.DNSTap.RemotePort),
		)
		connTimeout := time.Duration(c.config.Loggers.DNSTap.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch c.transport {
		case netlib.SocketUnix:
			address = c.config.Loggers.DNSTap.RemoteAddress
			if len(c.config.Loggers.DNSTap.SockPath) > 0 {
				address = c.config.Loggers.DNSTap.SockPath
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
				InsecureSkipVerify: c.config.Loggers.DNSTap.TLSInsecure,
				MinVersion:         c.config.Loggers.DNSTap.TLSMinVersion,
				CAFile:             c.config.Loggers.DNSTap.CAFile,
				CertFile:           c.config.Loggers.DNSTap.CertFile,
				KeyFile:            c.config.Loggers.DNSTap.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netlib.SocketTCP, address, tlsConfig)
			}
		default:
			c.logger.Fatal("logger=dnstap - invalid transport:", c.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			c.LogError("%s", err)
			c.LogInfo("retry to connect in %d seconds", c.config.Loggers.DNSTap.RetryInterval)
			time.Sleep(time.Duration(c.config.Loggers.DNSTap.RetryInterval) * time.Second)
			continue
		}

		c.transportConn = conn

		// block until framestream is ready
		c.transportReady <- true

		// block until an error occured, need to reconnect
		c.transportReconnect <- true
	}
}

func (c *DnstapSender) FlushBuffer(buf *[]dnsutils.DNSMessage) {

	var data []byte
	var err error
	frame := &framestream.Frame{}

	for _, dm := range *buf {
		// update identity ?
		if c.config.Loggers.DNSTap.OverwriteIdentity {
			dm.DNSTap.Identity = c.config.Loggers.DNSTap.ServerID
		}

		// encode dns message to dnstap protobuf binary
		data, err = dm.ToDNSTap()
		if err != nil {
			c.LogError("failed to encode to DNStap protobuf: %s", err)
			continue
		}

		// send the frame
		frame.Write(data)
		if err := c.fs.SendFrame(frame); err != nil {
			c.LogError("send frame error %s", err)
			c.fsReady = false
			<-c.transportReconnect
			break
		}
	}

	// reset buffer
	*buf = nil
}

func (c *DnstapSender) Run() {
	c.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := c.GetDefaultRoutes()
	droppedRoutes, droppedNames := c.GetDroppedRoutes()

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
				for i := range droppedRoutes {
					select {
					case droppedRoutes[i] <- dm: // Successful send to logger channel
					default:
						c.dropped <- droppedNames[i]
					}
				}
				continue
			}

			// send to next ?
			for i := range defaultRoutes {
				select {
				case defaultRoutes[i] <- dm: // Successful send to logger channel
				default:
					c.dropped <- defaultNames[i]
				}
			}

			// send to output channel
			c.outputChan <- dm
		}
	}
	c.LogInfo("run terminated")
}

func (c *DnstapSender) Process() {
	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(c.config.Loggers.DNSTap.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	nextStanzaBufferInterval := 10 * time.Second
	nextStanzaBufferFull := time.NewTimer(nextStanzaBufferInterval)

	c.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-c.stopProcess:
			// closing remote connection if exist
			c.Disconnect()

			c.doneProcess <- true
			break PROCESS_LOOP

		case stanzaName := <-c.dropped:
			if _, ok := c.droppedCount[stanzaName]; !ok {
				c.droppedCount[stanzaName] = 1
			} else {
				c.droppedCount[stanzaName]++
			}

		// init framestream
		case <-c.transportReady:
			c.LogInfo("transport connected with success")
			// frame stream library
			r := bufio.NewReader(c.transportConn)
			w := bufio.NewWriter(c.transportConn)
			c.fs = framestream.NewFstrm(r, w, c.transportConn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

			// init framestream protocol
			if err := c.fs.InitSender(); err != nil {
				c.LogError("sender protocol initialization error %s", err)
				c.fsReady = false
				c.transportConn.Close()
				<-c.transportReconnect
			} else {
				c.fsReady = true
				c.LogInfo("framestream initialized with success")
			}
		// incoming dns message to process
		case dm, opened := <-c.outputChan:
			if !opened {
				c.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !c.fsReady {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= c.config.Loggers.DNSTap.BufferSize {
				c.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			// force to flush the buffer
			if len(bufferDm) > 0 {
				c.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)

		case <-nextStanzaBufferFull.C:
			for v, k := range c.droppedCount {
				if k > 0 {
					c.LogError("stanza[%s] buffer is full, %d packet(s) dropped", v, k)
					c.droppedCount[v] = 0
				}
			}
			nextStanzaBufferFull.Reset(nextStanzaBufferInterval)
		}
	}
	c.LogInfo("processing terminated")
}
