package collectors

import (
	"bufio"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapTcp struct {
	done       chan bool
	listen     net.Listener
	conns      []net.Conn
	listenIP   string
	listenPort int
	generators []dnsutils.Worker
	config     *dnsutils.Config
	logger     *logger.Logger
}

func NewDnstapTcp(generators []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger) *DnstapTcp {
	logger.Info("collector dnstap tcp - enabled")
	s := &DnstapTcp{
		done:       make(chan bool),
		config:     config,
		generators: generators,
		logger:     logger,
	}
	s.ReadConfig()
	return s
}

func (c *DnstapTcp) Generators() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.generators {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *DnstapTcp) ReadConfig() {
	c.listenIP = c.config.Collectors.DnstapTcp.ListenIP
	c.listenPort = c.config.Collectors.DnstapTcp.ListenPort
}

func (c *DnstapTcp) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.logger.Info("collector dnstap tcp - %s - new connection\n", peer)

	// start dnstap consumer
	dnstap_processor := processors.NewDnstapProcessor(c.config, c.logger)
	go dnstap_processor.Run(c.Generators())

	// frame stream library
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

	// init framestream receiver
	if err := fs.InitReceiver(); err != nil {
		c.logger.Error("collector dnstap tcp - error stream receiver initialization: %s", err)
		return
	} else {
		c.logger.Info("collector dnstap tcp - receiver framestream initialized")
	}

	// process incoming frame and send it to dnstap consumer channel
	if err := fs.ProcessFrame(dnstap_processor.GetChannel()); err != nil {
		c.logger.Error("collector dnstap tcp - transport error: %s", err)
	}

	// stop all processors
	dnstap_processor.Stop()

	c.logger.Info("collector dnstap tcp - %s - connection closed\n", peer)
}

func (c *DnstapTcp) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *DnstapTcp) Stop() {
	c.logger.Info("collector dnstap tcp - stopping...")

	// closing properly current connections if exists
	for _, conn := range c.conns {
		peer := conn.RemoteAddr().String()
		c.logger.Info("collector dnstap tcp - %s - closing connection...", peer)
		conn.Close()
	}
	// Finally close the listener to unblock accept
	c.logger.Info("collector dnstap tcp - stop listening...")
	c.listen.Close()

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *DnstapTcp) Listen() error {
	c.logger.Info("collector dnstap tcp - running in background...")
	listener, err := net.Listen("tcp", c.listenIP+":"+strconv.Itoa(c.listenPort))
	if err != nil {
		return err
	}
	c.logger.Info("collector dnstap tcp - is listening on %s", listener.Addr())
	c.listen = listener
	return nil
}

func (c *DnstapTcp) Run() {
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			c.logger.Fatal("collector dnstap tcp listening failed: ", err)
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

	c.logger.Info("collector dnstap tcp - run terminated")
	c.done <- true
}
