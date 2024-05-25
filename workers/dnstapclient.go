package workers

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/segmentio/kafka-go/compress"
)

type DnstapSender struct {
	*GenericWorker
	fs                                 *framestream.Fstrm
	fsReady                            bool
	transport                          string
	transportConn                      net.Conn
	transportReady, transportReconnect chan bool
}

func NewDnstapSender(config *pkgconfig.Config, logger *logger.Logger, name string) *DnstapSender {
	w := &DnstapSender{GenericWorker: NewGenericWorker(config, logger, name, "dnstap", config.Loggers.DNSTap.ChannelBufferSize, pkgconfig.DefaultMonitor)}
	w.transportReady = make(chan bool)
	w.transportReconnect = make(chan bool)
	w.ReadConfig()
	return w
}

func (w *DnstapSender) ReadConfig() {
	w.transport = w.GetConfig().Loggers.DNSTap.Transport

	// begin backward compatibility
	if w.GetConfig().Loggers.DNSTap.TLSSupport {
		w.transport = netutils.SocketTLS
	}
	if len(w.GetConfig().Loggers.DNSTap.SockPath) > 0 {
		w.transport = netutils.SocketUnix
	}
	// end

	// get hostname or global one
	if w.GetConfig().Loggers.DNSTap.ServerID == "" {
		w.GetConfig().Loggers.DNSTap.ServerID = w.GetConfig().GetServerIdentity()
	}

	if !netutils.IsValidTLS(w.GetConfig().Loggers.DNSTap.TLSMinVersion) {
		w.LogFatal(pkgconfig.PrefixLogWorker + "invalid tls min version")
	}
}

func (w *DnstapSender) Disconnect() {
	if w.transportConn != nil {
		// reset framestream and ignore errors
		w.LogInfo("closing framestream")
		w.fs.ResetSender()

		// closing tcp
		w.LogInfo("closing tcp connection")
		w.transportConn.Close()
		w.LogInfo("closed")
	}
}

func (w *DnstapSender) ConnectToRemote() {
	for {
		if w.transportConn != nil {
			w.transportConn.Close()
			w.transportConn = nil
		}

		address := net.JoinHostPort(
			w.GetConfig().Loggers.DNSTap.RemoteAddress,
			strconv.Itoa(w.GetConfig().Loggers.DNSTap.RemotePort),
		)
		connTimeout := time.Duration(w.GetConfig().Loggers.DNSTap.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch w.transport {
		case netutils.SocketUnix:
			address = w.GetConfig().Loggers.DNSTap.RemoteAddress
			if len(w.GetConfig().Loggers.DNSTap.SockPath) > 0 {
				address = w.GetConfig().Loggers.DNSTap.SockPath
			}
			w.LogInfo("connecting to %s://%s", w.transport, address)
			conn, err = net.DialTimeout(w.transport, address, connTimeout)

		case netutils.SocketTCP:
			w.LogInfo("connecting to %s://%s", w.transport, address)
			conn, err = net.DialTimeout(w.transport, address, connTimeout)

		case netutils.SocketTLS:
			w.LogInfo("connecting to %s://%s", w.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := netutils.TLSOptions{
				InsecureSkipVerify: w.GetConfig().Loggers.DNSTap.TLSInsecure, MinVersion: w.GetConfig().Loggers.DNSTap.TLSMinVersion,
				CAFile: w.GetConfig().Loggers.DNSTap.CAFile, CertFile: w.GetConfig().Loggers.DNSTap.CertFile, KeyFile: w.GetConfig().Loggers.DNSTap.KeyFile,
			}

			tlsConfig, err = netutils.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netutils.SocketTCP, address, tlsConfig)
			}
		default:
			w.LogFatal("invalid transport:", w.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			w.LogError("%s", err)
			w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.DNSTap.RetryInterval)
			time.Sleep(time.Duration(w.GetConfig().Loggers.DNSTap.RetryInterval) * time.Second)
			continue
		}

		w.transportConn = conn

		// block until framestream is ready
		w.transportReady <- true

		// block until an error occurred, need to reconnect
		w.transportReconnect <- true
	}
}

func (w *DnstapSender) FlushBuffer(buf *[]dnsutils.DNSMessage) {

	var data []byte
	var err error
	bulkFrame := &framestream.Frame{}
	subFrame := &framestream.Frame{}

	for _, dm := range *buf {
		// update identity ?
		if w.GetConfig().Loggers.DNSTap.OverwriteIdentity {
			dm.DNSTap.Identity = w.GetConfig().Loggers.DNSTap.ServerID
		}

		// encode dns message to dnstap protobuf binary
		data, err = dm.ToDNSTap(w.GetConfig().Loggers.DNSTap.ExtendedSupport)
		if err != nil {
			w.LogError("failed to encode to DNStap protobuf: %s", err)
			continue
		}

		if w.GetConfig().Loggers.DNSTap.Compression == pkgconfig.CompressNone {
			// send the frame
			bulkFrame.Write(data)
			if err := w.fs.SendFrame(bulkFrame); err != nil {
				w.LogError("send frame error %s", err)
				w.fsReady = false
				<-w.transportReconnect
				break
			}
		} else {
			subFrame.Write(data)
			bulkFrame.AppendData(subFrame.Data())
		}
	}

	if w.GetConfig().Loggers.DNSTap.Compression != pkgconfig.CompressNone {
		bulkFrame.Encode()
		if err := w.fs.SendCompressedFrame(&compress.GzipCodec, bulkFrame); err != nil {
			w.LogError("send bulk frame error %s", err)
			w.fsReady = false
			<-w.transportReconnect
		}
	}

	// reset buffer
	*buf = nil
}

func (w *DnstapSender) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// init remote conn
	go w.ConnectToRemote()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

		// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *DnstapSender) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(w.GetConfig().Loggers.DNSTap.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	w.LogInfo("ready to process")
	for {
		select {
		case <-w.OnLoggerStopped():
			// closing remote connection if exist
			w.Disconnect()
			return

		// init framestream
		case <-w.transportReady:
			w.LogInfo("transport connected with success")
			// frame stream library
			fsReader := bufio.NewReader(w.transportConn)
			fsWriter := bufio.NewWriter(w.transportConn)
			w.fs = framestream.NewFstrm(fsReader, fsWriter, w.transportConn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

			// init framestream protocol
			if err := w.fs.InitSender(); err != nil {
				w.LogError("sender protocol initialization error %s", err)
				w.fsReady = false
				w.transportConn.Close()
				<-w.transportReconnect
			} else {
				w.fsReady = true
				w.LogInfo("framestream initialized with success")
			}
			// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !w.fsReady {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= w.GetConfig().Loggers.DNSTap.BufferSize {
				w.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			// force to flush the buffer
			if len(bufferDm) > 0 {
				w.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
}
