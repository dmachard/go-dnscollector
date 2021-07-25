package collectors

import (
	"bufio"
	"net"
	"os"
	"time"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapUnix struct {
	done       chan bool
	listen     net.Listener
	conns      []net.Conn
	sockPath   string
	generators []common.Worker
	config     *common.Config
	logger     *logger.Logger
}

func NewDnstapUnix(generators []common.Worker, config *common.Config, logger *logger.Logger) *DnstapUnix {
	logger.Info("collector dnstap unix - enabled")
	s := &DnstapUnix{
		done:       make(chan bool),
		generators: generators,
		config:     config,
		logger:     logger,
	}
	s.ReadConfig()
	return s
}

func (c *DnstapUnix) Generators() []chan dnsmessage.DnsMessage {
	channels := []chan dnsmessage.DnsMessage{}
	for _, p := range c.generators {
		channels = append(channels, p.Channel())
	}
	return channels
}
func (c *DnstapUnix) ReadConfig() {
	c.sockPath = c.config.Collectors.DnstapUnix.SockPath
}

func (c *DnstapUnix) Channel() chan dnsmessage.DnsMessage {
	return nil
}

func (c *DnstapUnix) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.logger.Info("collector dnstap unix receiver - %s - new connection\n", peer)

	// start dnstap consumer
	dnstap_consumer := dnsmessage.NewDnstapConsumer(c.logger)
	go dnstap_consumer.Run(c.Generators())

	// frame stream library
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

	// init framestream protocol
	if err := fs.InitReceiver(); err != nil {
		c.logger.Error("collector dnstap unix receiver - error protocol initialization %s", err)
		return
	} else {
		c.logger.Info("collector dnstap unix receiver - incoming framestream initialized")
	}

	// loop to wait incoming data frame
	// process incoming frame and send it to dnstap consumer
	if err := fs.ProcessFrame(dnstap_consumer.GetChannel()); err != nil {
		c.logger.Error("collector dnstap unix receiver - transport error: %s", err)
	}

	// stop dnstap consumer
	dnstap_consumer.Stop()

	//close(ch_dnstap)
	c.logger.Info("collector dnstap unix receiver - %s - connection closed\n", peer)
}

func (c *DnstapUnix) Stop() {
	c.logger.Info("collector dnstap unix receiver - stopping...")

	// closing properly current connections if exists
	c.logger.Info("collector dnstap unix receiver - closing current connections...")
	for _, conn := range c.conns {
		conn.Close()
	}
	// Finally close the listener to unblock accept
	c.logger.Info("collector dnstap unix receiver - stop listening...")
	c.listen.Close()

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *DnstapUnix) Listen() error {
	c.logger.Info("collector dnstap unix receiver - running in background...")

	_ = os.Remove(c.sockPath)

	listener, err := net.Listen("unix", c.sockPath)
	if err != nil {
		return err
	}
	c.logger.Info("collector dnstap unix receiver - is listening on %s", listener.Addr())
	c.listen = listener
	return nil
}

func (c *DnstapUnix) Run() {
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			c.logger.Fatal("collector dnstap unix listening failed: ", err)
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

	c.logger.Info("collector dnstap unix receiver - run terminated")
	c.done <- true
}
