package collectors

import (
	"bufio"
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapProxifier struct {
	*pkgutils.Collector
	listen      net.Listener
	sockPath    string
	connCounter uint64
	connWG      sync.WaitGroup
	connCleanup chan bool
}

func NewDnstapProxifier(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *DnstapProxifier {
	s := &DnstapProxifier{
		Collector:   pkgutils.NewCollector(config, logger, name, "dnstaprelay"),
		connCleanup: make(chan bool),
	}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
}

func (c *DnstapProxifier) ReadConfig() {
	if !pkgconfig.IsValidTLS(c.GetConfig().Collectors.DnstapProxifier.TLSMinVersion) {
		c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] dnstaprelay - invalid tls min version")
	}

	c.sockPath = c.GetConfig().Collectors.DnstapProxifier.SockPath
}

func (c *DnstapProxifier) Loggers() []chan dnsutils.DNSMessage {
	channels := []chan dnsutils.DNSMessage{}
	for _, p := range c.GetDefaultRoutes() {
		channels = append(channels, p.GetInputChannel())
	}
	return channels
}

func (c *DnstapProxifier) HandleFrame(recvFrom chan []byte, sendTo []chan dnsutils.DNSMessage) {
	defer func() {
		c.LogInfo("frame handler terminated")
	}()

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

func (c *DnstapProxifier) HandleConn(conn net.Conn, connID uint64, forceClose chan bool, wg *sync.WaitGroup) {
	// close connection on function exit
	defer func() {
		c.LogInfo("conn #%d - connection handler terminated", connID)
		conn.Close()
		wg.Done()
	}()

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

	// goroutine to close the connection properly
	cleanup := make(chan struct{})
	go func() {
		defer func() {
			c.LogInfo("conn #%d - cleanup connection handler terminated", connID)
		}()

		for {
			select {
			case <-forceClose:
				c.LogInfo("conn #%d - force to cleanup the connection handler", connID)
				conn.Close()
				close(recvChan)
				return
			case <-cleanup:
				c.LogInfo("conn #%d - cleanup the connection handler", connID)
				close(recvChan)
				return
			}
		}
	}()

	// process incoming frame and send it to recv channel
	err := fs.ProcessFrame(recvChan)
	if err != nil {
		if netlib.IsClosedConnectionError(err) {
			c.LogInfo("conn #%d - connection closed with peer %s", connID, peer)
		} else {
			c.LogError("conn #%d - transport error: %s", connID, err)
		}

		close(cleanup)
	}

}

func (c *DnstapProxifier) Stop() {
	// closing properly current connections if exists
	c.LogInfo("closing connected peers...")
	close(c.connCleanup)
	c.connWG.Wait()

	// stop the collector
	c.Collector.Stop()
}

func (c *DnstapProxifier) Listen() error {
	var err error
	var listener net.Listener
	addrlisten := c.GetConfig().Collectors.DnstapProxifier.ListenIP + ":" + strconv.Itoa(c.GetConfig().Collectors.DnstapProxifier.ListenPort)

	if len(c.sockPath) > 0 {
		_ = os.Remove(c.sockPath)
	}

	// listening with tls enabled ?
	if c.GetConfig().Collectors.DnstapProxifier.TLSSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.GetConfig().Collectors.DnstapProxifier.CertFile, c.GetConfig().Collectors.DnstapProxifier.KeyFile)
		if err != nil {
			c.LogFatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = pkgconfig.TLSVersion[c.GetConfig().Collectors.DnstapProxifier.TLSMinVersion]

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
	c.LogInfo("running in background...")
	defer func() {
		c.LogInfo("run terminated")
		c.StopIsDone()
	}()

	if err := c.Listen(); err != nil {
		c.LogFatal("collector dnstap listening failed: ", err)
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

	for {
		select {
		case <-c.OnStop():
			c.listen.Close()
			close(acceptChan)
			return

		// save the new config
		case cfg := <-c.NewConfig():
			c.SetConfig(cfg)
			c.ReadConfig()

		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			// handle the connection
			c.connWG.Add(1)
			connID := atomic.AddUint64(&c.connCounter, 1)
			go c.HandleConn(conn, connID, c.connCleanup, &c.connWG)
		}
	}
}
