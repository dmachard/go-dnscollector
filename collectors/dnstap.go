package collectors

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/segmentio/kafka-go/compress"
)

type Dnstap struct {
	*pkgutils.Collector
	listen      net.Listener
	sockPath    string
	connMode    string
	connCounter uint64
	connWG      sync.WaitGroup
	connCleanup chan bool
}

func NewDnstap(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *Dnstap {
	s := &Dnstap{
		Collector:   pkgutils.NewCollector(config, logger, name, "dnstap"),
		connCleanup: make(chan bool),
	}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
}

func (c *Dnstap) ReadConfig() {
	config := c.GetConfig().Collectors.Dnstap
	switch {
	case !pkgconfig.IsValidTLS(config.TLSMinVersion):
		c.LogFatal("collector=dnstap - invalid tls min version")
	case len(config.SockPath) > 0:
		c.sockPath = config.SockPath
		c.connMode = "unix"
	case config.TLSSupport:
		c.connMode = "tls"
	default:
		c.connMode = "tcp"
	}
}

func (c *Dnstap) HandleConn(conn net.Conn, connID uint64, forceClose chan bool, wg *sync.WaitGroup) {
	// close connection on function exit
	defer func() {
		c.LogInfo("conn #%d - connection handler terminated", connID)
		netlib.Close(conn, c.GetConfig().Collectors.Dnstap.ResetConn)
		wg.Done()
	}()

	// get peer address
	peer := conn.RemoteAddr().String()
	peerName := netlib.GetPeerName(peer)
	c.LogInfo("new connection #%d from %s (%s)", connID, peer, peerName)

	// start dnstap processor and run it
	dnstapProcessor := processors.NewDNSTapProcessor(int(connID), peerName, c.GetConfig(), c.GetLogger(), c.GetName(), c.GetConfig().Collectors.Dnstap.ChannelBufferSize)
	go dnstapProcessor.Run(c.GetDefaultRoutes(), c.GetDroppedRoutes())

	// init frame stream library
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

	// framestream as receiver
	if err := fs.InitReceiver(); err != nil {
		c.LogError("conn #%d - stream initialization: %s", connID, err)
	} else {
		c.LogInfo("conn #%d - receiver framestream initialized", connID)
	}

	// process incoming frame and send it to dnstap consumer channel
	var err error
	var frame *framestream.Frame
	cleanup := make(chan struct{})

	// goroutine to close the connection properly
	go func() {
		defer func() {
			dnstapProcessor.Stop()
			c.LogInfo("conn #%d - cleanup connection handler terminated", connID)
		}()

		for {
			select {
			case <-forceClose:
				c.LogInfo("conn #%d - force to cleanup the connection handler", connID)
				netlib.Close(conn, c.GetConfig().Collectors.Dnstap.ResetConn)
				return
			case <-cleanup:
				c.LogInfo("conn #%d - cleanup the connection handler", connID)
				return
			}
		}
	}()

	// handle incoming frame
	for {
		if c.GetConfig().Collectors.Dnstap.Compression == pkgconfig.CompressNone {
			frame, err = fs.RecvFrame(false)
		} else {
			frame, err = fs.RecvCompressedFrame(&compress.GzipCodec, false)
		}
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
				c.LogError("conn #%d - framestream reader error: %s", connID, err)
			}
			// exit goroutine
			close(cleanup)
			break
		}

		if frame.IsControl() {
			if err := fs.ResetReceiver(frame); err != nil {
				if errors.Is(err, io.EOF) {
					c.LogInfo("conn #%d - framestream reseted by sender", connID)
				} else {
					c.LogError("conn #%d - unexpected control framestream: %s", connID, err)
				}

			}

			// exit goroutine
			close(cleanup)
			break
		}

		if c.GetConfig().Collectors.Dnstap.Compression == pkgconfig.CompressNone {
			// send payload to the channel
			select {
			case dnstapProcessor.GetChannel() <- frame.Data(): // Successful send to channel
			default:
				c.ProcessorIsBusy()
			}
		} else {
			// ignore first 4 bytes
			data := frame.Data()[4:]
			validFrame := true
			for len(data) >= 4 {
				// get frame size
				payloadSize := binary.BigEndian.Uint32(data[:4])
				data = data[4:]

				// enough next data ?
				if uint32(len(data)) < payloadSize {
					validFrame = false
					break
				}
				// send payload to the channel
				select {
				case dnstapProcessor.GetChannel() <- data[:payloadSize]: // Successful send to channel
				default:
					c.ProcessorIsBusy()
				}

				// continue for next
				data = data[payloadSize:]
			}
			if !validFrame {
				c.LogError("conn #%d - invalid compressed frame received", connID)
				continue
			}
		}
	}
}

func (c *Dnstap) Stop() {
	// closing properly current connections if exists
	c.LogInfo("closing connected peers...")
	close(c.connCleanup)
	c.connWG.Wait()

	// stop the collector
	c.Collector.Stop()
}

func (c *Dnstap) Listen() error {
	var err error
	var listener net.Listener
	addrlisten := c.GetConfig().Collectors.Dnstap.ListenIP + ":" + strconv.Itoa(c.GetConfig().Collectors.Dnstap.ListenPort)

	if len(c.sockPath) > 0 {
		_ = os.Remove(c.sockPath)
	}

	// listening with tls enabled ?
	if c.GetConfig().Collectors.Dnstap.TLSSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.GetConfig().Collectors.Dnstap.CertFile, c.GetConfig().Collectors.Dnstap.KeyFile)
		if err != nil {
			c.LogFatal("loading certificate failed:", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = pkgconfig.TLSVersion[c.GetConfig().Collectors.Dnstap.TLSMinVersion]

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
	c.LogInfo("is listening on %s://%s", c.connMode, listener.Addr())
	c.listen = listener
	return nil
}

func (c *Dnstap) Run() {
	c.LogInfo("running in background...")
	defer func() {
		c.LogInfo("run terminated")
		c.StopIsDone()
	}()

	if err := c.Listen(); err != nil {
		c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] dnstap listening failed: ", err)
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

		// new incoming connection
		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			if (c.connMode == "tls" || c.connMode == "tcp") && c.GetConfig().Collectors.Dnstap.RcvBufSize > 0 {
				before, actual, err := netlib.SetSockRCVBUF(
					conn,
					c.GetConfig().Collectors.Dnstap.RcvBufSize,
					c.GetConfig().Collectors.Dnstap.TLSSupport,
				)
				if err != nil {
					c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] dnstap - unable to set SO_RCVBUF: ", err)
				}
				c.LogInfo("set SO_RCVBUF option, value before: %d, desired: %d, actual: %d", before,
					c.GetConfig().Collectors.Dnstap.RcvBufSize, actual)
			}

			// handle the connection
			c.connWG.Add(1)
			connID := atomic.AddUint64(&c.connCounter, 1)
			go c.HandleConn(conn, connID, c.connCleanup, &c.connWG)
		}

	}
}
