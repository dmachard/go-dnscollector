package collectors

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type Dnstap struct {
	doneRun          chan bool
	doneMonitor      chan bool
	stopRun          chan bool
	stopMonitor      chan bool
	stopCalled       bool
	listen           net.Listener
	conns            []net.Conn
	sockPath         string
	defaultRoutes    []pkgutils.Worker
	droppedRoutes    []pkgutils.Worker
	config           *pkgconfig.Config
	configChan       chan *pkgconfig.Config
	logger           *logger.Logger
	name             string
	connMode         string
	connID           int
	droppedCount     int
	droppedProcessor chan int
	tapProcessors    []processors.DNSTapProcessor
	sync.RWMutex
}

func NewDnstap(loggers []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *Dnstap {
	logger.Info(pkgutils.PrefixLogCollector+"[%s] dnstap - enabled", name)
	s := &Dnstap{
		doneRun:          make(chan bool),
		doneMonitor:      make(chan bool),
		stopRun:          make(chan bool),
		stopMonitor:      make(chan bool),
		droppedProcessor: make(chan int),
		config:           config,
		configChan:       make(chan *pkgconfig.Config),
		defaultRoutes:    loggers,
		logger:           logger,
		name:             name,
	}
	s.ReadConfig()
	return s
}

func (c *Dnstap) GetName() string { return c.name }

func (c *Dnstap) AddDroppedRoute(wrk pkgutils.Worker) {
	c.droppedRoutes = append(c.droppedRoutes, wrk)
}

func (c *Dnstap) AddDefaultRoute(wrk pkgutils.Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *Dnstap) SetLoggers(loggers []pkgutils.Worker) {
	c.defaultRoutes = loggers
}

func (c *Dnstap) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetRoutes(c.defaultRoutes)
}

func (c *Dnstap) ReadConfig() {
	if !pkgconfig.IsValidTLS(c.config.Collectors.Dnstap.TLSMinVersion) {
		c.logger.Fatal("collector=dnstap - invalid tls min version")
	}

	c.sockPath = c.config.Collectors.Dnstap.SockPath
	c.connMode = "tcp"

	if len(c.config.Collectors.Dnstap.SockPath) > 0 {
		c.connMode = "unix"
	} else if c.config.Collectors.Dnstap.TLSSupport {
		c.connMode = "tls"
	}
}

func (c *Dnstap) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration...")
	c.configChan <- config
}

func (c *Dnstap) LogInfo(msg string, v ...interface{}) {
	c.logger.Info(pkgutils.PrefixLogCollector+"["+c.name+"] dnstap - "+msg, v...)
}

func (c *Dnstap) LogError(msg string, v ...interface{}) {
	c.logger.Error(pkgutils.PrefixLogCollector+"["+c.name+" dnstap - "+msg, v...)
}

func (c *Dnstap) LogConnInfo(connID int, msg string, v ...interface{}) {
	prefix := fmt.Sprintf(pkgutils.PrefixLogCollector+"[%s] dnstap#%d - ", c.name, connID)
	c.logger.Info(prefix+msg, v...)
}

func (c *Dnstap) LogConnError(connID int, msg string, v ...interface{}) {
	prefix := fmt.Sprintf(pkgutils.PrefixLogCollector+"[%s] dnstap#%d - ", c.name, connID)
	c.logger.Error(prefix+msg, v...)
}

func (c *Dnstap) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	var connID int
	c.Lock()
	c.connID++
	connID = c.connID
	c.Unlock()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.LogInfo("new connection #%d from %s", connID, peer)

	// start dnstap processor
	dnstapProcessor := processors.NewDNSTapProcessor(
		connID,
		c.config,
		c.logger,
		c.name,
		c.config.Collectors.Dnstap.ChannelBufferSize,
	)
	c.Lock()
	c.tapProcessors = append(c.tapProcessors, dnstapProcessor)
	c.Unlock()

	// run processor
	go dnstapProcessor.Run(c.defaultRoutes, c.droppedRoutes)

	// frame stream library
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

	// init framestream receiver
	if err := fs.InitReceiver(); err != nil {
		c.LogConnError(connID, "stream initialization: %s", err)
	} else {
		c.LogConnInfo(connID, "receiver framestream initialized")
	}

	// process incoming frame and send it to dnstap consumer channel
	var err error
	var frame *framestream.Frame
	for {
		frame, err = fs.RecvFrame(false)
		if err != nil {
			connClosed := false

			var opErr *net.OpError
			if errors.As(err, &opErr) {
				if errors.Is(opErr, net.ErrClosed) {
					connClosed = true
				}
			}
			if errors.Is(err, io.EOF) {
				connClosed = true
			}

			if connClosed {
				c.LogConnInfo(connID, "connection closed with peer %s", peer)
			} else {
				c.LogConnError(connID, "framestream reader error: %s", err)
			}

			// the Stop function is already called, don't stop again
			if !c.stopCalled {
				dnstapProcessor.Stop()
			}
			break
		}

		if frame.IsControl() {
			if err := fs.ResetReceiver(frame); err != nil {
				if errors.Is(err, io.EOF) {
					c.LogConnInfo(connID, "framestream reseted by sender")
				} else {
					c.LogConnError(connID, "unexpected control framestream - %s", err)
				}

			}
			break
		}

		// send payload to the channel
		select {
		case dnstapProcessor.GetChannel() <- frame.Data(): // Successful send to channel
		default:
			c.droppedProcessor <- 1
		}
	}

	// to avoid lock if the Stop function is already called
	if c.stopCalled {
		c.LogConnInfo(connID, "connection handler exited")
		return
	}

	// here the connection is closed,
	// then removes the current tap processor from the list
	c.Lock()
	for i, t := range c.tapProcessors {
		if t.ConnID == connID {
			c.tapProcessors = append(c.tapProcessors[:i], c.tapProcessors[i+1:]...)
		}
	}

	// finnaly removes the current connection from the list
	for j, cn := range c.conns {
		if cn == conn {
			c.conns = append(c.conns[:j], c.conns[j+1:]...)
			conn = nil
		}
	}
	c.Unlock()

	c.LogConnInfo(connID, "connection handler terminated")
}

func (c *Dnstap) GetInputChannel() chan dnsutils.DNSMessage {
	return nil
}

func (c *Dnstap) Stop() {
	c.Lock()
	defer c.Unlock()

	// to avoid some lock situations when the remose side closes
	// the connection at the same time of this Stop function
	c.stopCalled = true
	c.LogInfo("stopping...")

	// stop all powerdns processors
	c.LogInfo("stopping processors...")
	for _, tapProc := range c.tapProcessors {
		tapProc.Stop()
	}

	// closing properly current connections if exists
	c.LogInfo("closing connected peers...")
	for _, conn := range c.conns {
		netlib.Close(conn, c.config.Collectors.Dnstap.ResetConn)
	}

	// Finally close the listener to unblock accept
	c.LogInfo("stop listening...")
	c.listen.Close()

	// stop monitor goroutine
	c.LogInfo("stopping monitor...")
	c.stopMonitor <- true
	<-c.doneMonitor

	// read done channel and block until run is terminated
	c.LogInfo("stopping run...")
	c.stopRun <- true
	<-c.doneRun
}

func (c *Dnstap) Listen() error {
	c.Lock()
	defer c.Unlock()

	c.LogInfo("running in background...")

	var err error
	var listener net.Listener
	addrlisten := c.config.Collectors.Dnstap.ListenIP + ":" + strconv.Itoa(c.config.Collectors.Dnstap.ListenPort)

	if len(c.sockPath) > 0 {
		_ = os.Remove(c.sockPath)
	}

	// listening with tls enabled ?
	if c.config.Collectors.Dnstap.TLSSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.config.Collectors.Dnstap.CertFile, c.config.Collectors.Dnstap.KeyFile)
		if err != nil {
			c.logger.Fatal("loading certificate failed:", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = pkgconfig.TLSVersion[c.config.Collectors.Dnstap.TLSMinVersion]

		if len(c.sockPath) > 0 {
			listener, err = tls.Listen(netlib.SocketUnix, c.sockPath, tlsConfig)
		} else {
			listener, err = tls.Listen(netlib.SocketTCP, addrlisten, tlsConfig)
		}

	} else {
		// basic listening
		if len(c.sockPath) > 0 {
			listener, err = net.Listen(netlib.SocketUnix, c.sockPath)
		} else {
			listener, err = net.Listen(netlib.SocketTCP, addrlisten)
		}
	}

	// something is wrong ?
	if err != nil {
		return err
	}
	c.LogInfo("is listening on %s://%s", c.connMode, listener.Addr())
	c.listen = listener
	return nil
}

func (c *Dnstap) MonitorCollector() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
MONITOR_LOOP:
	for {
		select {
		case <-c.droppedProcessor:
			c.droppedCount++
		case <-c.stopMonitor:
			close(c.droppedProcessor)
			bufferFull.Stop()
			c.doneMonitor <- true
			break MONITOR_LOOP
		case <-bufferFull.C:
			if c.droppedCount > 0 {
				c.LogError("processor buffer is full, %d packet(s) dropped", c.droppedCount)
				c.droppedCount = 0
			}
			bufferFull.Reset(watchInterval)
		}
	}
	c.LogInfo("monitor terminated")
}

func (c *Dnstap) Run() {
	c.LogInfo("starting collector...")
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			prefixlog := fmt.Sprintf("[%s] ", c.name)
			c.logger.Fatal(prefixlog+"collector=dnstap listening failed: ", err)
		}
	}

	// start goroutine to count dropped messsages
	go c.MonitorCollector()

	// goroutine to Accept() blocks waiting for new connection.
	acceptChan := make(chan net.Conn)
	go func() {
		for {
			conn, err := c.listen.Accept()
			if err != nil {
				return
			}
			acceptChan <- conn
		}
	}()

RUN_LOOP:
	for {
		select {
		case <-c.stopRun:
			close(acceptChan)
			c.doneRun <- true
			break RUN_LOOP

		case cfg := <-c.configChan:

			// save the new config
			c.config = cfg
			c.ReadConfig()

			// refresh config for all conns
			for i := range c.tapProcessors {
				c.tapProcessors[i].ConfigChan <- cfg
			}

		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			if (c.connMode == "tls" || c.connMode == "tcp") && c.config.Collectors.Dnstap.RcvBufSize > 0 {
				before, actual, err := netlib.SetSockRCVBUF(
					conn,
					c.config.Collectors.Dnstap.RcvBufSize,
					c.config.Collectors.Dnstap.TLSSupport,
				)
				if err != nil {
					c.logger.Fatal("Unable to set SO_RCVBUF: ", err)
				}
				c.LogInfo("set SO_RCVBUF option, value before: %d, desired: %d, actual: %d", before,
					c.config.Collectors.Dnstap.RcvBufSize, actual)
			}

			// to avoid lock if the Stop function is already called
			if c.stopCalled {
				continue
			}

			c.Lock()
			c.conns = append(c.conns, conn)
			c.Unlock()
			go c.HandleConn(conn)
		}

	}
	c.LogInfo("run terminated")
}
