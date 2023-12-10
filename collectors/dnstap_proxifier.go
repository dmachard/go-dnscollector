package collectors

import (
	"bufio"
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapProxifier struct {
	doneRun    chan bool
	stopRun    chan bool
	listen     net.Listener
	conns      []net.Conn
	sockPath   string
	loggers    []dnsutils.Worker
	config     *pkgconfig.Config
	configChan chan *pkgconfig.Config
	logger     *logger.Logger
	name       string
	stopping   bool
}

func NewDnstapProxifier(loggers []dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *DnstapProxifier {
	logger.Info("[%s] collector=dnstaprelay - enabled", name)
	s := &DnstapProxifier{
		doneRun:    make(chan bool),
		stopRun:    make(chan bool),
		config:     config,
		configChan: make(chan *pkgconfig.Config),
		loggers:    loggers,
		logger:     logger,
		name:       name,
	}
	s.ReadConfig()
	return s
}

func (c *DnstapProxifier) GetName() string { return c.name }

func (c *DnstapProxifier) AddRoute(wrk dnsutils.Worker) {
	c.loggers = append(c.loggers, wrk)
}

func (c *DnstapProxifier) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *DnstapProxifier) Loggers() []chan dnsutils.DNSMessage {
	channels := []chan dnsutils.DNSMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *DnstapProxifier) ReadConfig() {
	if !pkgconfig.IsValidTLS(c.config.Collectors.DnstapProxifier.TLSMinVersion) {
		c.logger.Fatal("collector=dnstaprelay - invalid tls min version")
	}

	c.sockPath = c.config.Collectors.DnstapProxifier.SockPath
}

func (c *DnstapProxifier) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration...")
	c.configChan <- config
}

func (c *DnstapProxifier) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] collector=dnstaprelay - "+msg, v...)
}

func (c *DnstapProxifier) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] collector=dnstaprelay - "+msg, v...)
}

func (c *DnstapProxifier) HandleFrame(recvFrom chan []byte, sendTo []chan dnsutils.DNSMessage) {
	for data := range recvFrom {
		// init DNS message container
		dm := dnsutils.DNSMessage{}
		dm.Init()

		// register payload
		dm.DNSTap.Payload = data

		// forward to outputs
		for i := range sendTo {
			sendTo[i] <- dm
		}
	}
}

func (c *DnstapProxifier) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.LogInfo("new connection from %s\n", peer)

	recvChan := make(chan []byte, 512)
	go c.HandleFrame(recvChan, c.Loggers())

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

	// process incoming frame and send it to recv channel
	err := fs.ProcessFrame(recvChan)
	if err != nil && !c.stopping {
		c.LogError("transport error: %s", err)
	}

	close(recvChan)

	c.LogInfo("%s - connection closed\n", peer)
}

func (c *DnstapProxifier) Channel() chan dnsutils.DNSMessage {
	return nil
}

func (c *DnstapProxifier) Stop() {
	c.LogInfo("stopping...")
	c.stopping = true

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
	c.stopRun <- true
	<-c.doneRun
}

func (c *DnstapProxifier) Listen() error {
	c.LogInfo("running in background...")

	var err error
	var listener net.Listener
	addrlisten := c.config.Collectors.DnstapProxifier.ListenIP + ":" + strconv.Itoa(c.config.Collectors.DnstapProxifier.ListenPort)

	if len(c.sockPath) > 0 {
		_ = os.Remove(c.sockPath)
	}

	// listening with tls enabled ?
	if c.config.Collectors.DnstapProxifier.TLSSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.config.Collectors.DnstapProxifier.CertFile, c.config.Collectors.DnstapProxifier.KeyFile)
		if err != nil {
			c.logger.Fatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = pkgconfig.TLSVersion[c.config.Collectors.DnstapProxifier.TLSMinVersion]

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
	c.LogInfo("is listening on %s", listener.Addr())
	c.listen = listener
	return nil
}

func (c *DnstapProxifier) Run() {
	c.LogInfo("starting collector...")
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			c.logger.Fatal("collector dnstap listening failed: ", err)
		}
	}

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

		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			c.conns = append(c.conns, conn)
			go c.HandleConn(conn)
		}
	}

	c.LogInfo("run terminated")
}
