package collectors

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type Dnstap struct {
	done          chan bool
	cleanup       chan bool
	listen        net.Listener
	conns         []net.Conn
	sockPath      string
	loggers       []dnsutils.Worker
	config        *dnsutils.Config
	logger        *logger.Logger
	name          string
	connMode      string
	droppedCount  int
	dropped       chan int
	tapProcessors []DnstapProcessor
	sync.RWMutex
}

func NewDnstap(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *Dnstap {
	logger.Info("[%s] dnstap collector - enabled", name)
	s := &Dnstap{
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

func (c *Dnstap) GetName() string { return c.name }

func (c *Dnstap) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *Dnstap) Loggers() ([]chan dnsutils.DnsMessage, []string) {
	channels := []chan dnsutils.DnsMessage{}
	names := []string{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
		names = append(names, p.GetName())
	}
	return channels, names
}

func (c *Dnstap) ReadConfig() {
	if !dnsutils.IsValidTLS(c.config.Collectors.Dnstap.TlsMinVersion) {
		c.logger.Fatal("collector dnstap - invalid tls min version")
	}

	c.sockPath = c.config.Collectors.Dnstap.SockPath

	if len(c.config.Collectors.Dnstap.SockPath) > 0 {
		c.connMode = "unix"
	} else if c.config.Collectors.Dnstap.TlsSupport {
		c.connMode = "tls"
	} else {
		c.connMode = "tcp"
	}
}

func (c *Dnstap) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] dnstap collector - "+msg, v...)
}

func (c *Dnstap) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] dnstap collector - "+msg, v...)
}

func (c *Dnstap) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.LogInfo("new connection from %s\n", peer)

	// start dnstap subprocessor
	dnstapProcessor := NewDnstapProcessor(c.config, c.logger, c.name, c.config.Collectors.Dnstap.ChannelBufferSize)
	c.tapProcessors = append(c.tapProcessors, dnstapProcessor)
	go dnstapProcessor.Run(c.Loggers())

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
				c.LogInfo("connection closed with peer %s\n", peer)
				close(dnstapProcessor.GetChannel())
				dnstapProcessor.Stop()
			} else {
				c.LogError("framestream reader error: %s", err)
			}
			break
		}

		// send payload to the channel
		select {
		case dnstapProcessor.GetChannel() <- frame.Data(): // Successful send to channel
		default:
			c.dropped <- 1
		}
	}
}

func (c *Dnstap) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *Dnstap) Stop() {
	c.Lock()
	defer c.Unlock()

	c.LogInfo("stopping...")

	// stop all powerdns processors
	for _, tapProc := range c.tapProcessors {
		tapProc.Stop()
	}

	// closing properly current connections if exists
	c.LogInfo("closing connected peers...")
	for _, conn := range c.conns {
		peer := conn.RemoteAddr().String()
		c.LogInfo("%s - closing connection...", peer)
		netlib.Close(conn, c.config.Collectors.Dnstap.ResetConn)
	}
	// Finally close the listener to unblock accept
	c.LogInfo("stop listening...")
	c.listen.Close()

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
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
	if c.config.Collectors.Dnstap.TlsSupport {
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
		tlsConfig.MinVersion = dnsutils.TLS_VERSION[c.config.Collectors.Dnstap.TlsMinVersion]

		if len(c.sockPath) > 0 {
			listener, err = tls.Listen(dnsutils.SOCKET_UNIX, c.sockPath, tlsConfig)
		} else {
			listener, err = tls.Listen(dnsutils.SOCKET_TCP, addrlisten, tlsConfig)
		}

	} else {
		// basic listening
		if len(c.sockPath) > 0 {
			listener, err = net.Listen(dnsutils.SOCKET_UNIX, c.sockPath)
		} else {
			listener, err = net.Listen(dnsutils.SOCKET_TCP, addrlisten)
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

func (c *Dnstap) DropsFollowing() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
	for {
		select {
		case <-c.dropped:
			c.droppedCount++
		case <-c.cleanup:
			c.LogInfo("cleanup called")
			return
		case <-bufferFull.C:
			if c.droppedCount > 0 {
				c.LogError("recv buffer is full, %d packet(s) dropped", c.droppedCount)
				c.droppedCount = 0
			}
			bufferFull.Reset(watchInterval)
		}
	}
}

func (c *Dnstap) Run() {
	c.LogInfo("starting collector...")
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			c.logger.Fatal("collector dnstap listening failed: ", err)
		}
	}

	go c.DropsFollowing()

	for {
		// Accept() blocks waiting for new connection.
		conn, err := c.listen.Accept()
		if err != nil {
			break
		}

		if (c.connMode == "tls" || c.connMode == "tcp") && c.config.Collectors.Dnstap.RcvBufSize > 0 {
			before, actual, err := netlib.SetSock_RCVBUF(
				conn,
				c.config.Collectors.Dnstap.RcvBufSize,
				c.config.Collectors.Dnstap.TlsSupport,
			)
			if err != nil {
				c.logger.Fatal("Unable to set SO_RCVBUF: ", err)
			}
			c.LogInfo("set SO_RCVBUF option, value before: %d, desired: %d, actual: %d", before,
				c.config.Collectors.Dnstap.RcvBufSize, actual)
		}

		c.conns = append(c.conns, conn)
		go c.HandleConn(conn)
	}

	c.LogInfo("run terminated")
	c.done <- true
}
