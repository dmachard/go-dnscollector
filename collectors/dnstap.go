package collectors

import (
	"bufio"
	"encoding/binary"
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
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/segmentio/kafka-go/compress"
)

type Dnstap struct {
	*pkgutils.GenericWorker
	connCounter uint64
}

func NewDnstap(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *Dnstap {
	s := &Dnstap{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "dnstap", pkgutils.DefaultBufferSize)}
	s.SetDefaultRoutes(next)
	s.CheckConfig()
	return s
}

func (w *Dnstap) CheckConfig() {
	if !pkgconfig.IsValidTLS(w.GetConfig().Collectors.Dnstap.TLSMinVersion) {
		w.LogFatal(pkgutils.PrefixLogCollector + "[" + w.GetName() + "] dnstap - invalid tls min version")
	}
}

func (w *Dnstap) HandleConn(conn net.Conn, connID uint64, forceClose chan bool, wg *sync.WaitGroup) {
	// close connection on function exit
	defer func() {
		w.LogInfo("conn #%d - connection handler terminated", connID)
		netutils.Close(conn, w.GetConfig().Collectors.Dnstap.ResetConn)
		wg.Done()
	}()

	// get peer address
	peer := conn.RemoteAddr().String()
	peerName := netutils.GetPeerName(peer)
	w.LogInfo("new connection #%d from %s (%s)", connID, peer, peerName)

	// start dnstap processor and run it
	dnstapProcessor := processors.NewDNSTapProcessor(int(connID), peerName, w.GetConfig(), w.GetLogger(), w.GetName(), w.GetConfig().Collectors.Dnstap.ChannelBufferSize)
	go dnstapProcessor.Run(w.GetDefaultRoutes(), w.GetDroppedRoutes())

	// init frame stream library
	fsReader := bufio.NewReader(conn)
	fsWriter := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(fsReader, fsWriter, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

	// framestream as receiver
	if err := fs.InitReceiver(); err != nil {
		w.LogError("conn #%d - stream initialization: %s", connID, err)
	} else {
		w.LogInfo("conn #%d - receiver framestream initialized", connID)
	}

	// process incoming frame and send it to dnstap consumer channel
	var err error
	var frame *framestream.Frame
	cleanup := make(chan struct{})

	// goroutine to close the connection properly
	go func() {
		defer func() {
			dnstapProcessor.Stop()
			w.LogInfo("conn #%d - cleanup connection handler terminated", connID)
		}()

		for {
			select {
			case <-forceClose:
				w.LogInfo("conn #%d - force to cleanup the connection handler", connID)
				netutils.Close(conn, w.GetConfig().Collectors.Dnstap.ResetConn)
				return
			case <-cleanup:
				w.LogInfo("conn #%d - cleanup the connection handler", connID)
				return
			}
		}
	}()

	// handle incoming frame
	for {
		if w.GetConfig().Collectors.Dnstap.Compression == pkgconfig.CompressNone {
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
				w.LogInfo("conn #%d - connection closed with peer %s", connID, peer)
			} else {
				w.LogError("conn #%d - framestream reader error: %s", connID, err)
			}
			// exit goroutine
			close(cleanup)
			break
		}

		if frame.IsControl() {
			if err := fs.ResetReceiver(frame); err != nil {
				if errors.Is(err, io.EOF) {
					w.LogInfo("conn #%d - framestream reseted by sender", connID)
				} else {
					w.LogError("conn #%d - unexpected control framestream: %s", connID, err)
				}

			}

			// exit goroutine
			close(cleanup)
			break
		}

		if w.GetConfig().Collectors.Dnstap.Compression == pkgconfig.CompressNone {
			// send payload to the channel
			select {
			case dnstapProcessor.GetChannel() <- frame.Data(): // Successful send to channel
			default:
				w.ProcessorIsBusy()
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
					w.ProcessorIsBusy()
				}

				// continue for next
				data = data[payloadSize:]
			}
			if !validFrame {
				w.LogError("conn #%d - invalid compressed frame received", connID)
				continue
			}
		}
	}
}

func (w *Dnstap) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	var connWG sync.WaitGroup
	connCleanup := make(chan bool)
	cfg := w.GetConfig().Collectors.Dnstap

	// start to listen
	listener, err := netutils.StartToListen(
		cfg.ListenIP, cfg.ListenPort, cfg.SockPath,
		cfg.TLSSupport, pkgconfig.TLSVersion[cfg.TLSMinVersion],
		cfg.CertFile, cfg.KeyFile)
	if err != nil {
		w.LogFatal(pkgutils.PrefixLogCollector+"["+w.GetName()+"] listen error: ", err)
	}
	w.LogInfo("listening on %s", listener.Addr())

	// goroutine to Accept() blocks waiting for new connection.
	acceptChan := make(chan net.Conn)
	netutils.AcceptConnections(listener, acceptChan)

	// main loop
	for {
		select {
		case <-w.OnStop():
			w.LogInfo("stop to listen...")
			listener.Close()

			w.LogInfo("closing connected peers...")
			close(connCleanup)
			connWG.Wait()
			return

		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.CheckConfig()

		// new incoming connection
		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			if len(cfg.SockPath) == 0 && cfg.RcvBufSize > 0 {
				before, actual, err := netutils.SetSockRCVBUF(conn, cfg.RcvBufSize, cfg.TLSSupport)
				if err != nil {
					w.LogFatal(pkgutils.PrefixLogCollector+"["+w.GetName()+"] unable to set SO_RCVBUF: ", err)
				}
				w.LogInfo("set SO_RCVBUF option, value before: %d, desired: %d, actual: %d", before, cfg.RcvBufSize, actual)
			}

			// handle the connection
			connWG.Add(1)
			connID := atomic.AddUint64(&w.connCounter, 1)
			go w.HandleConn(conn, connID, connCleanup, &connWG)
		}

	}
}
