package collectors

import (
	"bufio"
	"crypto/tls"
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
	done     chan bool
	listen   net.Listener
	conns    []net.Conn
	sockPath string
	loggers  []dnsutils.Worker
	config   *dnsutils.Config
	logger   *logger.Logger
}

func NewDnstap(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger) *Dnstap {
	logger.Info("collector dnstap - enabled")
	s := &Dnstap{
		done:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
	}
	s.ReadConfig()
	return s
}

func (c *Dnstap) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *Dnstap) ReadConfig() {
	c.sockPath = c.config.Collectors.Dnstap.SockPath
}

func (o *Dnstap) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("collector dnstap - "+msg, v...)
}

func (o *Dnstap) LogError(msg string, v ...interface{}) {
	o.logger.Error("collector dnstap - "+msg, v...)
}

func (c *Dnstap) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.LogInfo("%s - new connection\n", peer)

	// start dnstap subprocessor
	dnstap_subprocessor := subprocessors.NewDnstapProcessor(c.config, c.logger)
	go dnstap_subprocessor.Run(c.Loggers())

	// frame stream library
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

	// init framestream receiver
	if err := fs.InitReceiver(); err != nil {
		c.LogError("error stream receiver initialization: %s", err)
		return
	} else {
		c.LogInfo("receiver framestream initialized")
	}

	// process incoming frame and send it to dnstap consumer channel
	if err := fs.ProcessFrame(dnstap_subprocessor.GetChannel()); err != nil {
		c.LogError("transport error: %s", err)
	}

	// stop all subprocessors
	dnstap_subprocessor.Stop()

	c.LogInfo("%s - connection closed\n", peer)
}

func (c *Dnstap) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *Dnstap) Stop() {
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

func (c *Dnstap) Listen() error {
	c.LogInfo("running in background...")

	var err error
	var listener net.Listener
	addrlisten := c.config.Collectors.Dnstap.ListenIP + ":" + strconv.Itoa(c.config.Collectors.Dnstap.ListenPort)

	if len(c.sockPath) > 0 {
		_ = os.Remove(c.sockPath)
	}

	// listening with tls enabled ?
	if c.config.Collectors.Dnstap.TlsSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.config.Collectors.Dnstap.CertFile, c.config.Collectors.Dnstap.KeyFile)
		if err != nil {
			c.logger.Fatal("loading certificate failed:", err)
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}

		if len(c.sockPath) > 0 {
			listener, err = tls.Listen("unix", c.sockPath, config)
		} else {
			listener, err = tls.Listen("tcp", addrlisten, config)
		}

	} else {
		// basic listening
		if len(c.sockPath) > 0 {
			listener, err = net.Listen("unix", c.sockPath)
		} else {
			listener, err = net.Listen("tcp", addrlisten)
		}
	}

	// something is wrong ?
	if err != nil {
		return err
	}
	c.LogInfo("is listening on %s", listener.Addr())
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

	c.LogInfo("run terminated")
	c.done <- true
}
