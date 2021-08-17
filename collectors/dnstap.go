package collectors

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/subprocessors"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type Dnstap struct {
	done       chan bool
	listen     net.Listener
	conns      []net.Conn
	listenIP   string
	listenPort int
	sockPath   string
	generators []dnsutils.Worker
	config     *dnsutils.Config
	logger     *logger.Logger
}

func NewDnstap(generators []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger) *Dnstap {
	logger.Info("collector dnstap - enabled")
	s := &Dnstap{
		done:       make(chan bool),
		config:     config,
		generators: generators,
		logger:     logger,
	}
	s.ReadConfig()
	return s
}

func (c *Dnstap) Generators() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.generators {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *Dnstap) ReadConfig() {
	c.listenIP = c.config.Collectors.Dnstap.ListenIP
	c.listenPort = c.config.Collectors.Dnstap.ListenPort
	c.sockPath = c.config.Collectors.Dnstap.SockPath
}

func (c *Dnstap) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.logger.Info("collector dnstap - %s - new connection\n", peer)

	// start dnstap consumer
	dnstap_processor := subprocessors.NewDnstapProcessor(c.config, c.logger)
	go dnstap_processor.Run(c.Generators())

	// frame stream library
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

	// init framestream receiver
	if err := fs.InitReceiver(); err != nil {
		c.logger.Error("collector dnstap - error stream receiver initialization: %s", err)
		return
	} else {
		c.logger.Info("collector dnstap - receiver framestream initialized")
	}

	// process incoming frame and send it to dnstap consumer channel
	if err := fs.ProcessFrame(dnstap_processor.GetChannel()); err != nil {
		c.logger.Error("collector dnstap - transport error: %s", err)
	}

	// stop all processors
	dnstap_processor.Stop()

	c.logger.Info("collector dnstap - %s - connection closed\n", peer)
}

func (c *Dnstap) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *Dnstap) Stop() {
	c.logger.Info("collector dnstap - stopping...")

	// closing properly current connections if exists
	for _, conn := range c.conns {
		peer := conn.RemoteAddr().String()
		c.logger.Info("collector dnstap - %s - closing connection...", peer)
		conn.Close()
	}
	// Finally close the listener to unblock accept
	c.logger.Info("collector dnstap - stop listening...")
	c.listen.Close()

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *Dnstap) Listen() error {
	c.logger.Info("collector dnstap - running in background...")

	var err error
	var listener net.Listener
	if len(c.sockPath) > 0 {
		_ = os.Remove(c.sockPath)
		listener, err = net.Listen("unix", c.sockPath)

	} else {
		listener, err = net.Listen("tcp", c.listenIP+":"+strconv.Itoa(c.listenPort))

	}
	if err != nil {
		return err
	}
	c.logger.Info("collector dnstap - is listening on %s", listener.Addr())
	c.listen = listener
	return nil
}

func (c *Dnstap) Run() {
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

	c.logger.Info("collector dnstap - run terminated")
	c.done <- true
}
