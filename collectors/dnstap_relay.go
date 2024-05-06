package collectors

import (
	"bufio"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapProxifier struct {
	*pkgutils.GenericWorker
	connCounter uint64
}

func NewDnstapProxifier(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *DnstapProxifier {
	s := &DnstapProxifier{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "dnstaprelay", pkgutils.DefaultBufferSize)}
	s.SetDefaultRoutes(next)
	s.CheckConfig()
	return s
}

func (c *DnstapProxifier) CheckConfig() {
	if !pkgconfig.IsValidTLS(c.GetConfig().Collectors.DnstapProxifier.TLSMinVersion) {
		c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] dnstaprelay - invalid tls min version")
	}
}

func (c *DnstapProxifier) HandleFrame(recvFrom chan []byte, sendTo []chan dnsutils.DNSMessage) {
	defer c.LogInfo("frame handler terminated")

	dm := dnsutils.DNSMessage{}

	for data := range recvFrom {
		// init DNS message container
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
	defaultRoutes, _ := pkgutils.GetRoutes(c.GetDefaultRoutes())
	go c.HandleFrame(recvChan, defaultRoutes)

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
		defer c.LogInfo("conn #%d - cleanup connection handler terminated", connID)

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
		if netutils.IsClosedConnectionError(err) {
			c.LogInfo("conn #%d - connection closed with peer %s", connID, peer)
		} else {
			c.LogError("conn #%d - transport error: %s", connID, err)
		}

		close(cleanup)
	}
}

func (c *DnstapProxifier) StartCollect() {
	c.LogInfo("worker is starting collection")
	defer func() {
		c.StopIsDone()
	}()

	var connWG sync.WaitGroup
	connCleanup := make(chan bool)

	// start to listen
	listener, err := netutils.StartToListen(
		c.GetConfig().Collectors.DnstapProxifier.ListenIP, c.GetConfig().Collectors.DnstapProxifier.ListenPort,
		c.GetConfig().Collectors.DnstapProxifier.SockPath,
		c.GetConfig().Collectors.DnstapProxifier.TLSSupport, pkgconfig.TLSVersion[c.GetConfig().Collectors.DnstapProxifier.TLSMinVersion],
		c.GetConfig().Collectors.DnstapProxifier.CertFile, c.GetConfig().Collectors.DnstapProxifier.KeyFile)
	if err != nil {
		c.LogFatal("collector dnstaprelay listening failed: ", err)
	}
	c.LogInfo("listening on %s", listener.Addr())

	// goroutine to Accept() and blocks waiting for new connection.
	acceptChan := make(chan net.Conn)
	netutils.AcceptConnections(listener, acceptChan)

	// main loop
	for {
		select {
		case <-c.OnStop():
			c.LogInfo("stop to listen...")
			listener.Close()

			c.LogInfo("closing connected peers...")
			close(connCleanup)
			connWG.Wait()
			return

		// save the new config
		case cfg := <-c.NewConfig():
			c.SetConfig(cfg)
			c.CheckConfig()

		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			// handle the connection
			connWG.Add(1)
			connID := atomic.AddUint64(&c.connCounter, 1)
			go c.HandleConn(conn, connID, connCleanup, &connWG)
		}
	}
}
