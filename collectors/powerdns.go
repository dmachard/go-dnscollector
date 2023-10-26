package collectors

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
)

type ProtobufPowerDNS struct {
	doneRun        chan bool
	doneMonitor    chan bool
	stopMonitor    chan bool
	cleanup        chan bool
	listen         net.Listener
	connId         int
	conns          []net.Conn
	loggers        []dnsutils.Worker
	config         *dnsutils.Config
	logger         *logger.Logger
	name           string
	droppedCount   int
	dropped        chan int
	pdnsProcessors []*PdnsProcessor
	sync.RWMutex
}

func NewProtobufPowerDNS(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *ProtobufPowerDNS {
	logger.Info("[%s] pdns collector - enabled", name)
	s := &ProtobufPowerDNS{
		doneRun:     make(chan bool),
		doneMonitor: make(chan bool),
		stopMonitor: make(chan bool),
		cleanup:     make(chan bool),
		dropped:     make(chan int),
		config:      config,
		loggers:     loggers,
		logger:      logger,
		name:        name,
	}
	s.ReadConfig()
	return s
}

func (c *ProtobufPowerDNS) GetName() string { return c.name }

func (c *ProtobufPowerDNS) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *ProtobufPowerDNS) Loggers() ([]chan dnsutils.DnsMessage, []string) {
	channels := []chan dnsutils.DnsMessage{}
	names := []string{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
		names = append(names, p.GetName())
	}
	return channels, names
}

func (c *ProtobufPowerDNS) ReadConfig() {
	if !dnsutils.IsValidTLS(c.config.Collectors.PowerDNS.TlsMinVersion) {
		c.logger.Fatal("collector=powerdns - invalid tls min version")
	}
}

func (c *ProtobufPowerDNS) ReloadConfig(config *dnsutils.Config) {
	c.LogInfo("reload config...")

	// save the new config
	c.config = config
	c.ReadConfig()

	// refresh config for all conns
	for i := range c.pdnsProcessors {
		c.pdnsProcessors[i].ReloadConfig(config)
	}
}

func (c *ProtobufPowerDNS) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] collector=powerdns - "+msg, v...)
}

func (c *ProtobufPowerDNS) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] collector=powerdns - "+msg, v...)
}

func (c *ProtobufPowerDNS) LogConnInfo(connId int, msg string, v ...interface{}) {
	prefix := fmt.Sprintf("[%s] collector=powerdns#%d - ", c.name, connId)
	c.logger.Info(prefix+msg, v...)
}

func (c *ProtobufPowerDNS) LogConnError(connId int, msg string, v ...interface{}) {
	prefix := fmt.Sprintf("[%s] collector=powerdns#%d - ", c.name, connId)
	c.logger.Error(prefix+msg, v...)
}

func (c *ProtobufPowerDNS) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	var connId int
	c.Lock()
	c.connId++
	connId = c.connId
	c.Unlock()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.LogConnInfo(connId, "new connection from %s", peer)

	// start protobuf subprocessor
	pdnsProc := NewPdnsProcessor(connId, c.config, c.logger, c.name, c.config.Collectors.PowerDNS.ChannelBufferSize)
	c.Lock()
	c.pdnsProcessors = append(c.pdnsProcessors, &pdnsProc)
	c.Unlock()
	go pdnsProc.Run(c.Loggers())

	r := bufio.NewReader(conn)
	pbs := powerdns_protobuf.NewProtobufStream(r, conn, 5*time.Second)

	var err error
	var payload *powerdns_protobuf.ProtoPayload
	for {
		payload, err = pbs.RecvPayload(false)
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
				c.LogConnInfo(connId, "connection closed with peer %s", peer)
			} else {
				c.LogConnError(connId, "powerdns reader error: %s", err)
			}

			// stop processor
			pdnsProc.Stop()
			break
		}

		// send payload to the channel
		select {
		case pdnsProc.GetChannel() <- payload.Data(): // Successful send
		default:
			c.dropped <- 1
		}
	}

	// here the connection is closed,
	// then removes the current tap processor from the list
	c.Lock()
	for i, t := range c.pdnsProcessors {
		if t.connId == connId {
			c.pdnsProcessors = append(c.pdnsProcessors[:i], c.pdnsProcessors[i+1:]...)
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

	c.LogConnInfo(connId, "connection handler terminated")
}

func (c *ProtobufPowerDNS) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *ProtobufPowerDNS) Stop() {
	c.Lock()
	defer c.Unlock()

	c.LogInfo("stopping...")

	// stop all powerdns processors
	c.LogInfo("stopping processors...")
	for _, pdnsProc := range c.pdnsProcessors {
		pdnsProc.Stop()
	}

	// closing properly current connections if exists
	c.LogInfo("closing connected peers...")
	for _, conn := range c.conns {
		peer := conn.RemoteAddr().String()
		c.LogInfo("%s - closing connection...", peer)
		netlib.Close(conn, c.config.Collectors.PowerDNS.ResetConn)
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
	<-c.doneRun
	close(c.doneRun)
}

func (c *ProtobufPowerDNS) Listen() error {
	c.Lock()
	defer c.Unlock()

	c.LogInfo("running in background...")

	var err error
	var listener net.Listener
	addrlisten := c.config.Collectors.PowerDNS.ListenIP + ":" + strconv.Itoa(c.config.Collectors.PowerDNS.ListenPort)

	// listening with tls enabled ?
	if c.config.Collectors.PowerDNS.TlsSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.config.Collectors.PowerDNS.CertFile, c.config.Collectors.PowerDNS.KeyFile)
		if err != nil {
			c.logger.Fatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = dnsutils.TLS_VERSION[c.config.Collectors.PowerDNS.TlsMinVersion]

		listener, err = tls.Listen(dnsutils.SOCKET_TCP, addrlisten, tlsConfig)
	} else {
		listener, err = net.Listen(dnsutils.SOCKET_TCP, addrlisten)
	}
	// something is wrong ?
	if err != nil {
		return err
	}
	c.LogInfo("is listening on %s", listener.Addr())
	c.listen = listener
	return nil
}

func (c *ProtobufPowerDNS) MonitorCollector() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
MONITOR_LOOP:
	for {
		select {
		case <-c.stopMonitor:
			close(c.dropped)
			bufferFull.Stop()
			c.doneMonitor <- true
			break MONITOR_LOOP
		case <-c.dropped:
			c.droppedCount++
		case <-bufferFull.C:
			if c.droppedCount > 0 {
				c.LogError("recv buffer is full, %d packet(s) dropped", c.droppedCount)
				c.droppedCount = 0
			}
			bufferFull.Reset(watchInterval)
		}
	}
	c.LogInfo("monitor terminated")
}

func (c *ProtobufPowerDNS) Run() {

	c.LogInfo("starting collector...")
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			prefixlog := fmt.Sprintf("[%s] ", c.name)
			c.logger.Fatal(prefixlog+"collector=powerdns listening failed: ", err)
		}
	}

	// start goroutine to count dropped messsages
	go c.MonitorCollector()

	for {
		// Accept() blocks waiting for new connection.
		conn, err := c.listen.Accept()
		if err != nil {
			break
		}

		if c.config.Collectors.Dnstap.RcvBufSize > 0 {
			before, actual, err := netlib.SetSock_RCVBUF(
				conn,
				c.config.Collectors.Dnstap.RcvBufSize,
				c.config.Collectors.Dnstap.TlsSupport,
			)
			if err != nil {
				c.logger.Fatal("Unable to set SO_RCVBUF: ", err)
			}
			c.LogInfo("set SO_RCVBUF option, value before: %d, desired: %d, actual: %d",
				before,
				c.config.Collectors.Dnstap.RcvBufSize,
				actual)
		}

		c.Lock()
		c.conns = append(c.conns, conn)
		c.Unlock()
		go c.HandleConn(conn)

	}

	c.LogInfo("run terminated")
	c.doneRun <- true
}
