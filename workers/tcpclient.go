package workers

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type TCPClient struct {
	*GenericWorker
	stopRead, doneRead                 chan bool
	textFormat                         []string
	transport                          string
	transportWriter                    *bufio.Writer
	transportConn                      net.Conn
	transportReady, transportReconnect chan bool
	writerReady                        bool
}

func NewTCPClient(config *pkgconfig.Config, logger *logger.Logger, name string) *TCPClient {
	w := &TCPClient{GenericWorker: NewGenericWorker(config, logger, name, "tcpclient", config.Loggers.TCPClient.ChannelBufferSize, pkgconfig.DefaultMonitor)}
	w.transportReady = make(chan bool)
	w.transportReconnect = make(chan bool)
	w.stopRead = make(chan bool)
	w.doneRead = make(chan bool)
	w.ReadConfig()
	return w
}

func (w *TCPClient) ReadConfig() {
	w.transport = w.GetConfig().Loggers.TCPClient.Transport

	// begin backward compatibility
	if w.GetConfig().Loggers.TCPClient.TLSSupport {
		w.transport = netutils.SocketTLS
	}
	if len(w.GetConfig().Loggers.TCPClient.SockPath) > 0 {
		w.transport = netutils.SocketUnix
	}
	// end

	if len(w.GetConfig().Loggers.TCPClient.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.TCPClient.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}
}

func (w *TCPClient) Disconnect() {
	if w.transportConn != nil {
		w.LogInfo("closing tcp connection")
		w.transportConn.Close()
	}
}

func (w *TCPClient) ReadFromConnection() {
	buffer := make([]byte, 4096)

	go func() {
		for {
			_, err := w.transportConn.Read(buffer)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					w.LogInfo("read from connection terminated")
					break
				}
				w.LogError("Error on reading: %s", err.Error())
			}
			// We just discard the data
		}
	}()

	// block goroutine until receive true event in stopRead channel
	<-w.stopRead
	w.doneRead <- true

	w.LogInfo("read goroutine terminated")
}

func (w *TCPClient) ConnectToRemote() {
	for {
		if w.transportConn != nil {
			w.transportConn.Close()
			w.transportConn = nil
		}

		address := w.GetConfig().Loggers.TCPClient.RemoteAddress + ":" + strconv.Itoa(w.GetConfig().Loggers.TCPClient.RemotePort)
		connTimeout := time.Duration(w.GetConfig().Loggers.TCPClient.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch w.transport {
		case netutils.SocketUnix:
			address = w.GetConfig().Loggers.TCPClient.RemoteAddress
			if len(w.GetConfig().Loggers.TCPClient.SockPath) > 0 {
				address = w.GetConfig().Loggers.TCPClient.SockPath
			}
			w.LogInfo("connecting to %s://%s", w.transport, address)
			conn, err = net.DialTimeout(w.transport, address, connTimeout)

		case netutils.SocketTCP:
			w.LogInfo("connecting to %s://%s", w.transport, address)
			conn, err = net.DialTimeout(w.transport, address, connTimeout)

		case netutils.SocketTLS:
			w.LogInfo("connecting to %s://%s", w.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := pkgconfig.TLSOptions{
				InsecureSkipVerify: w.GetConfig().Loggers.TCPClient.TLSInsecure,
				MinVersion:         w.GetConfig().Loggers.TCPClient.TLSMinVersion,
				CAFile:             w.GetConfig().Loggers.TCPClient.CAFile,
				CertFile:           w.GetConfig().Loggers.TCPClient.CertFile,
				KeyFile:            w.GetConfig().Loggers.TCPClient.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
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
			w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.TCPClient.RetryInterval)
			time.Sleep(time.Duration(w.GetConfig().Loggers.TCPClient.RetryInterval) * time.Second)
			continue
		}

		w.transportConn = conn

		// block until framestream is ready
		w.transportReady <- true

		// block until an error occurred, need to reconnect
		w.transportReconnect <- true
	}
}

func (w *TCPClient) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	for _, dm := range *buf {
		if w.GetConfig().Loggers.TCPClient.Mode == pkgconfig.ModeText {
			w.transportWriter.Write(dm.Bytes(w.textFormat,
				w.GetConfig().Global.TextFormatDelimiter,
				w.GetConfig().Global.TextFormatBoundary))
			w.transportWriter.WriteString(w.GetConfig().Loggers.TCPClient.PayloadDelimiter)
		}

		if w.GetConfig().Loggers.TCPClient.Mode == pkgconfig.ModeJSON {
			json.NewEncoder(w.transportWriter).Encode(dm)
			w.transportWriter.WriteString(w.GetConfig().Loggers.TCPClient.PayloadDelimiter)
		}

		if w.GetConfig().Loggers.TCPClient.Mode == pkgconfig.ModeFlatJSON {
			flat, err := dm.Flatten()
			if err != nil {
				w.LogError("flattening DNS message failed: %e", err)
				continue
			}
			json.NewEncoder(w.transportWriter).Encode(flat)
			w.transportWriter.WriteString(w.GetConfig().Loggers.TCPClient.PayloadDelimiter)
		}

		// flush the transport buffer
		err := w.transportWriter.Flush()
		if err != nil {
			w.LogError("send frame error", err.Error())
			w.writerReady = false
			<-w.transportReconnect
			break
		}
	}

	// reset buffer
	*buf = nil
}

func (w *TCPClient) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()

			w.stopRead <- true
			<-w.doneRead

			return

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
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
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

func (w *TCPClient) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(w.GetConfig().Loggers.TCPClient.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// init remote conn
	go w.ConnectToRemote()

	w.LogInfo("ready to process")
	for {
		select {
		case <-w.OnLoggerStopped():
			// closing remote connection if exist
			w.Disconnect()
			return

		case <-w.transportReady:
			w.LogInfo("transport connected with success")
			w.transportWriter = bufio.NewWriter(w.transportConn)
			w.writerReady = true

			// read from the connection until we stop
			go w.ReadFromConnection()

		// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !w.writerReady {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= w.GetConfig().Loggers.TCPClient.BufferSize {
				w.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !w.writerReady {
				bufferDm = nil
			}

			if len(bufferDm) > 0 {
				w.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)

		}
	}
}
