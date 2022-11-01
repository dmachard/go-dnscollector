package collectors

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
)

type ProtobufPowerDNS struct {
	done    chan bool
	listen  net.Listener
	conns   []net.Conn
	loggers []dnsutils.Worker
	config  *dnsutils.Config
	logger  *logger.Logger
	name    string
}

func NewProtobufPowerDNS(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *ProtobufPowerDNS {
	logger.Info("[%s] pdns collector - enabled", name)
	s := &ProtobufPowerDNS{
		done:    make(chan bool),
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
	pdns_subprocessor := NewPdnsProcessor(c.config, c.logger, c.name)
	go pdns_subprocessor.Run(c.Loggers())

	r := bufio.NewReader(conn)
	pbs := powerdns_protobuf.NewProtobufStream(r, conn, 5*time.Second)

	// process incoming protobuf payload
	if err := pbs.ProcessStream(pdns_subprocessor.GetChannel()); err != nil {
		c.LogError("transport error: %s", err)
	}

	c.LogInfo("%s - connection closed\n", peer)
}

func (c *ProtobufPowerDNS) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *ProtobufPowerDNS) Stop() {
	c.LogInfo("stopping...")

	// closing properly current connections if exists
	for _, conn := range c.conns {
		peer := conn.RemoteAddr().String()
		c.LogInfo("%s - closing connection...", peer)
		conn.Close()
	}
	// Finally close the listener to unblock accept
	c.LogInfo("stop listening...")
	c.listen.Close()

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *ProtobufPowerDNS) Listen() error {
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
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		listener, err = tls.Listen(dnsutils.SOCKET_TCP, addrlisten, config)
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

func (c *ProtobufPowerDNS) Run() {
	c.LogInfo("starting collector...")
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			c.logger.Fatal("collector dnstap listening failed: ", err)
		}
	}
	for {
		// Accept() blocks waiting for new connection.
		conn, err := c.listen.Accept()
		if err != nil {
			break
		}

		c.conns = append(c.conns, conn)
		go c.HandleConn(conn)

	}

	c.LogInfo("run terminated")
	c.done <- true
}
