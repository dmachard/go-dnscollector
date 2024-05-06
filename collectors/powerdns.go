package collectors

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
)

type ProtobufPowerDNS struct {
	*pkgutils.GenericWorker
	connCounter uint64
}

func NewProtobufPowerDNS(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *ProtobufPowerDNS {
	s := &ProtobufPowerDNS{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "powerdns", pkgutils.DefaultBufferSize)}
	s.SetDefaultRoutes(next)
	s.CheckConfig()
	return s
}

func (c *ProtobufPowerDNS) CheckConfig() {
	if !pkgconfig.IsValidTLS(c.GetConfig().Collectors.PowerDNS.TLSMinVersion) {
		c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] invalid tls min version")
	}
}

func (c *ProtobufPowerDNS) HandleConn(conn net.Conn, connID uint64, forceClose chan bool, wg *sync.WaitGroup) {
	// close connection on function exit
	defer func() {
		c.LogInfo("conn #%d - connection handler terminated", connID)
		netutils.Close(conn, c.GetConfig().Collectors.Dnstap.ResetConn)
		wg.Done()
	}()

	// get peer address
	peer := conn.RemoteAddr().String()
	peerName := netutils.GetPeerName(peer)
	c.LogInfo("new connection #%d from %s (%s)", connID, peer, peerName)

	// start protobuf subprocessor
	pdnsProcessor := processors.NewPdnsProcessor(int(connID), peerName, c.GetConfig(), c.GetLogger(), c.GetName(), c.GetConfig().Collectors.PowerDNS.ChannelBufferSize)
	go pdnsProcessor.Run(c.GetDefaultRoutes(), c.GetDroppedRoutes())

	r := bufio.NewReader(conn)
	pbs := powerdns_protobuf.NewProtobufStream(r, conn, 5*time.Second)

	var err error
	var payload *powerdns_protobuf.ProtoPayload
	cleanup := make(chan struct{})

	// goroutine to close the connection properly
	go func() {
		defer func() {
			pdnsProcessor.Stop()
			c.LogInfo("conn #%d - cleanup connection handler terminated", connID)
		}()

		for {
			select {
			case <-forceClose:
				c.LogInfo("conn #%d - force to cleanup the connection handler", connID)
				netutils.Close(conn, c.GetConfig().Collectors.Dnstap.ResetConn)
				return
			case <-cleanup:
				c.LogInfo("conn #%d - cleanup the connection handler", connID)
				return
			}
		}
	}()

	for {
		payload, err = pbs.RecvPayload(false)
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
				c.LogInfo("conn #%d - connection closed with peer %s", connID, peer)
			} else {
				c.LogError("conn #%d - powerdns reader error: %s", connID, err)
			}

			// exit goroutine
			close(cleanup)
			break
		}

		// send payload to the channel
		select {
		case pdnsProcessor.GetChannel() <- payload.Data(): // Successful send
		default:
			c.ProcessorIsBusy()
		}
	}
}

func (c *ProtobufPowerDNS) StartCollect() {
	c.LogInfo("worker is starting collection")
	defer func() {
		c.StopIsDone()
	}()

	var connWG sync.WaitGroup
	connCleanup := make(chan bool)
	cfg := c.GetConfig().Collectors.PowerDNS

	// start to listen
	listener, err := netutils.StartToListen(
		cfg.ListenIP, cfg.ListenPort, "",
		cfg.TLSSupport, pkgconfig.TLSVersion[cfg.TLSMinVersion],
		cfg.CertFile, cfg.KeyFile)
	if err != nil {
		c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] listening failed: ", err)
	}
	c.LogInfo("listening on %s", listener.Addr())

	// goroutine to Accept() blocks waiting for new connection.
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

			if c.GetConfig().Collectors.Dnstap.RcvBufSize > 0 {
				before, actual, err := netutils.SetSockRCVBUF(conn, cfg.RcvBufSize, cfg.TLSSupport)
				if err != nil {
					c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] unable to set SO_RCVBUF: ", err)
				}
				c.LogInfo("set SO_RCVBUF option, value before: %d, desired: %d, actual: %d", before, cfg.RcvBufSize, actual)
			}

			// handle the connection
			connWG.Add(1)
			connID := atomic.AddUint64(&c.connCounter, 1)
			go c.HandleConn(conn, connID, connCleanup, &connWG)

		}
	}
}
