package collectors

import (
	"bufio"
	"crypto/tls"
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
	done           chan bool
	cleanup        chan bool
	listen         net.Listener
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
		done:    make(chan bool),
		cleanup: make(chan bool),
		dropped: make(chan int),
		config:  config,
		loggers: loggers,
		logger:  logger,
		name:    name,
	}
	s.ReadConfig()
	return s
}

func (c *ProtobufPowerDNS) GetName() string { return c.name }

func (c *ProtobufPowerDNS) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *ProtobufPowerDNS) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *ProtobufPowerDNS) ReadConfig() {
	if !dnsutils.IsValidTLS(c.config.Collectors.PowerDNS.TlsMinVersion) {
		c.logger.Fatal("collector powerdns - invalid tls min version")
	}
}

func (c *ProtobufPowerDNS) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] pdns collector - "+msg, v...)
}

func (c *ProtobufPowerDNS) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] pdns collector - "+msg, v...)
}

func (c *ProtobufPowerDNS) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.LogInfo("%s - new connection\n", peer)

	// start protobuf subprocessor
	pdnsProc := NewPdnsProcessor(c.config, c.logger, c.name, c.config.Collectors.PowerDNS.ChannelBufferSize)
	c.pdnsProcessors = append(c.pdnsProcessors, &pdnsProc)
	go pdnsProc.Run(c.Loggers())

	r := bufio.NewReader(conn)
	pbs := powerdns_protobuf.NewProtobufStream(r, conn, 5*time.Second)

	var err error
	var payload *powerdns_protobuf.ProtoPayload
	for {
		payload, err = pbs.RecvPayload(false)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err == net.ErrClosed || err == io.EOF {
				c.LogInfo("connection closed with peer %s\n", peer)
				close(pdnsProc.GetChannel())
			} else {
				c.LogError("protobuf reader error: %s", err)
			}
			break
		}

		// drop packet if the channel is full to avoid a tcp zero windows
		if pdnsProc.ChannelIsFull() {
			c.dropped <- 1
			continue
		}

		// send payload to the channel
		pdnsProc.GetChannel() <- payload.Data()

	}
}

func (c *ProtobufPowerDNS) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *ProtobufPowerDNS) Stop() {
	c.Lock()
	defer c.Unlock()

	c.LogInfo("stopping...")

	// stop all powerdns processors
	for _, pdnsProc := range c.pdnsProcessors {
		pdnsProc.Stop()
	}

	// closing properly current connections if exists
	for _, conn := range c.conns {
		peer := conn.RemoteAddr().String()
		c.LogInfo("%s - closing connection...", peer)
		netlib.Close(conn, c.config.Collectors.PowerDNS.ResetConn)
	}

	// Finally close the listener to unblock accept
	c.LogInfo("stop listening...")
	c.listen.Close()

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
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

func (c *ProtobufPowerDNS) FollowChannel() {
	c.LogInfo("start to follow up incoming dropped packets...")

	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
	for {
		select {
		case <-c.cleanup:
			c.LogInfo("cleanup called")
			return
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
}

func (c *ProtobufPowerDNS) Run() {
	c.LogInfo("starting collector...")
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			c.logger.Fatal("collector dnstap listening failed: ", err)
		}
	}

	go c.FollowChannel()

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

		c.conns = append(c.conns, conn)
		go c.HandleConn(conn)

	}

	c.LogInfo("run terminated")
	c.done <- true
}
