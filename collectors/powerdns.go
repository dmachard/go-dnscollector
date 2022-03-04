package collectors

import (
	"bufio"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/subprocessors"
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
}

func NewProtobufPowerDNS(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger) *ProtobufPowerDNS {
	logger.Info("collector PowerDNS protobuf - enabled")
	s := &ProtobufPowerDNS{
		done:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
	}
	s.ReadConfig()
	return s
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

func (o *ProtobufPowerDNS) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("collector powerdns protobuf - "+msg, v...)
}

func (o *ProtobufPowerDNS) LogError(msg string, v ...interface{}) {
	o.logger.Error("collector powerdns protobuf - "+msg, v...)
}

func (c *ProtobufPowerDNS) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.LogInfo("%s - new connection\n", peer)

	// start protobuf subprocessor
	pdns_subprocessor := subprocessors.NewPdnsProcessor(c.config, c.logger)
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

	listener, err = net.Listen("tcp", addrlisten)

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
