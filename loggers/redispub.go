package loggers

import (
	"bufio"
	"bytes"
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
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type RedisPub struct {
	*pkgutils.GenericWorker
	stopRead, doneRead                 chan bool
	textFormat                         []string
	transport                          string
	transportWriter                    *bufio.Writer
	transportConn                      net.Conn
	transportReady, transportReconnect chan bool
	writerReady                        bool
}

func NewRedisPub(config *pkgconfig.Config, logger *logger.Logger, name string) *RedisPub {
	w := &RedisPub{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "redispub", config.Loggers.RedisPub.ChannelBufferSize)}
	w.stopRead = make(chan bool)
	w.doneRead = make(chan bool)
	w.transportReady = make(chan bool)
	w.transportReconnect = make(chan bool)
	w.ReadConfig()
	return w
}

func (w *RedisPub) ReadConfig() {

	w.transport = w.GetConfig().Loggers.RedisPub.Transport

	// begin backward compatibility
	if w.GetConfig().Loggers.RedisPub.TLSSupport {
		w.transport = netutils.SocketTLS
	}
	if len(w.GetConfig().Loggers.RedisPub.SockPath) > 0 {
		w.transport = netutils.SocketUnix
	}
	// end

	if len(w.GetConfig().Loggers.RedisPub.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.RedisPub.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}
}

func (w *RedisPub) Disconnect() {
	if w.transportConn != nil {
		w.LogInfo("closing redispub connection")
		w.transportConn.Close()
	}
}

func (w *RedisPub) ReadFromConnection() {
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

func (w *RedisPub) ConnectToRemote() {
	for {
		if w.transportConn != nil {
			w.transportConn.Close()
			w.transportConn = nil
		}

		address := w.GetConfig().Loggers.RedisPub.RemoteAddress + ":" + strconv.Itoa(w.GetConfig().Loggers.RedisPub.RemotePort)
		connTimeout := time.Duration(w.GetConfig().Loggers.RedisPub.ConnectTimeout) * time.Second

		var conn net.Conn
		var err error

		switch w.transport {
		case netutils.SocketUnix:
			address = w.GetConfig().Loggers.RedisPub.RemoteAddress
			if len(w.GetConfig().Loggers.RedisPub.SockPath) > 0 {
				address = w.GetConfig().Loggers.RedisPub.SockPath
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
				InsecureSkipVerify: w.GetConfig().Loggers.RedisPub.TLSInsecure,
				MinVersion:         w.GetConfig().Loggers.RedisPub.TLSMinVersion,
				CAFile:             w.GetConfig().Loggers.RedisPub.CAFile,
				CertFile:           w.GetConfig().Loggers.RedisPub.CertFile,
				KeyFile:            w.GetConfig().Loggers.RedisPub.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netutils.SocketTCP, address, tlsConfig)
			}

		default:
			w.LogFatal("logger=redispub - invalid transport:", w.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			w.LogError("%s", err)
			w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.RedisPub.RetryInterval)
			time.Sleep(time.Duration(w.GetConfig().Loggers.RedisPub.RetryInterval) * time.Second)
			continue
		}

		w.transportConn = conn

		// block until framestream is ready
		w.transportReady <- true

		// block until an error occurred, need to reconnect
		w.transportReconnect <- true
	}
}

func (w *RedisPub) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	// create escaping buffer
	escapeBuffer := new(bytes.Buffer)
	// create a new encoder that writes to the buffer
	encoder := json.NewEncoder(escapeBuffer)

	for _, dm := range *buf {
		escapeBuffer.Reset()

		cmd := "PUBLISH " + strconv.Quote(w.GetConfig().Loggers.RedisPub.RedisChannel) + " "
		w.transportWriter.WriteString(cmd)

		if w.GetConfig().Loggers.RedisPub.Mode == pkgconfig.ModeText {
			w.transportWriter.WriteString(strconv.Quote(dm.String(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)))
			w.transportWriter.WriteString(w.GetConfig().Loggers.RedisPub.PayloadDelimiter)
		}

		if w.GetConfig().Loggers.RedisPub.Mode == pkgconfig.ModeJSON {
			encoder.Encode(dm)
			w.transportWriter.WriteString(strconv.Quote(escapeBuffer.String()))
			w.transportWriter.WriteString(w.GetConfig().Loggers.RedisPub.PayloadDelimiter)
		}

		if w.GetConfig().Loggers.RedisPub.Mode == pkgconfig.ModeFlatJSON {
			flat, err := dm.Flatten()
			if err != nil {
				w.LogError("flattening DNS message failed: %e", err)
				continue
			}
			encoder.Encode(flat)
			w.transportWriter.WriteString(strconv.Quote(escapeBuffer.String()))
			w.transportWriter.WriteString(w.GetConfig().Loggers.RedisPub.PayloadDelimiter)
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

func (w *RedisPub) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := pkgutils.GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := pkgutils.GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, w.GetOutputChannel())
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), listChannel, 0)

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

func (w *RedisPub) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(w.GetConfig().Loggers.RedisPub.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// init remote conn
	go w.ConnectToRemote()

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
			if len(bufferDm) >= w.GetConfig().Loggers.RedisPub.BufferSize {
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
