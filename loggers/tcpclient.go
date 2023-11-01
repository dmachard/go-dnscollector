package loggers

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type TcpClient struct {
	stopProcess        chan bool
	doneProcess        chan bool
	stopRun            chan bool
	doneRun            chan bool
	inputChan          chan dnsutils.DnsMessage
	outputChan         chan dnsutils.DnsMessage
	config             *dnsutils.Config
	configChan         chan *dnsutils.Config
	logger             *logger.Logger
	textFormat         []string
	name               string
	transport          string
	transportWriter    *bufio.Writer
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	writerReady        bool
}

func NewTcpClient(config *dnsutils.Config, logger *logger.Logger, name string) *TcpClient {
	logger.Info("[%s] logger=tcpclient - enabled", name)
	s := &TcpClient{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		inputChan:          make(chan dnsutils.DnsMessage, config.Loggers.TcpClient.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DnsMessage, config.Loggers.TcpClient.ChannelBufferSize),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             logger,
		config:             config,
		configChan:         make(chan *dnsutils.Config),
		name:               name,
	}

	s.ReadConfig()

	return s
}

func (c *TcpClient) GetName() string { return c.name }

func (c *TcpClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *TcpClient) ReadConfig() {
	o.transport = o.config.Loggers.TcpClient.Transport

	// begin backward compatibility
	if o.config.Loggers.TcpClient.TlsSupport {
		o.transport = dnsutils.SOCKET_TLS
	}
	if len(o.config.Loggers.TcpClient.SockPath) > 0 {
		o.transport = dnsutils.SOCKET_UNIX
	}
	// end

	if len(o.config.Loggers.TcpClient.TextFormat) > 0 {
		o.textFormat = strings.Fields(o.config.Loggers.TcpClient.TextFormat)
	} else {
		o.textFormat = strings.Fields(o.config.Global.TextFormat)
	}
}

func (o *TcpClient) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload configuration!")
	o.configChan <- config
}

func (o *TcpClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger=tcpclient - "+msg, v...)
}

func (o *TcpClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger=tcpclient - "+msg, v...)
}

func (o *TcpClient) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *TcpClient) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *TcpClient) Disconnect() {
	if o.transportConn != nil {
		o.LogInfo("closing tcp connection")
		o.transportConn.Close()
	}
}

func (o *TcpClient) ConnectToRemote() {

	for {
		if o.transportConn != nil {
			o.transportConn.Close()
			o.transportConn = nil
		}

		address := o.config.Loggers.TcpClient.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.TcpClient.RemotePort)
		connTimeout := time.Duration(o.config.Loggers.TcpClient.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch o.transport {
		case dnsutils.SOCKET_UNIX:
			address = o.config.Loggers.TcpClient.RemoteAddress
			if len(o.config.Loggers.TcpClient.SockPath) > 0 {
				address = o.config.Loggers.TcpClient.SockPath
			}
			o.LogInfo("connecting to %s://%s", o.transport, address)
			conn, err = net.DialTimeout(o.transport, address, connTimeout)

		case dnsutils.SOCKET_TCP:
			o.LogInfo("connecting to %s://%s", o.transport, address)
			conn, err = net.DialTimeout(o.transport, address, connTimeout)

		case dnsutils.SOCKET_TLS:
			o.LogInfo("connecting to %s://%s", o.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := dnsutils.TlsOptions{
				InsecureSkipVerify: o.config.Loggers.TcpClient.TlsInsecure,
				MinVersion:         o.config.Loggers.TcpClient.TlsMinVersion,
				CAFile:             o.config.Loggers.TcpClient.CAFile,
				CertFile:           o.config.Loggers.TcpClient.CertFile,
				KeyFile:            o.config.Loggers.TcpClient.KeyFile,
			}

			tlsConfig, err = dnsutils.TlsClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, dnsutils.SOCKET_TCP, address, tlsConfig)
			}
		default:
			o.logger.Fatal("logger=dnstap - invalid transport:", o.transport, err)
		}

		// something is wrong during connection ?
		if err != nil {
			o.LogError("%s", err)
			o.LogInfo("retry to connect in %d seconds", o.config.Loggers.TcpClient.RetryInterval)
			time.Sleep(time.Duration(o.config.Loggers.TcpClient.RetryInterval) * time.Second)
			continue
		}

		o.transportConn = conn

		// block until framestream is ready
		o.transportReady <- true

		// block until an error occured, need to reconnect
		o.transportReconnect <- true
	}
}

func (o *TcpClient) FlushBuffer(buf *[]dnsutils.DnsMessage) {
	for _, dm := range *buf {
		if o.config.Loggers.TcpClient.Mode == dnsutils.MODE_TEXT {
			o.transportWriter.Write(dm.Bytes(o.textFormat,
				o.config.Global.TextFormatDelimiter,
				o.config.Global.TextFormatBoundary))
			o.transportWriter.WriteString(o.config.Loggers.TcpClient.PayloadDelimiter)
		}

		if o.config.Loggers.TcpClient.Mode == dnsutils.MODE_JSON {
			json.NewEncoder(o.transportWriter).Encode(dm)
			o.transportWriter.WriteString(o.config.Loggers.TcpClient.PayloadDelimiter)
		}

		if o.config.Loggers.TcpClient.Mode == dnsutils.MODE_FLATJSON {
			flat, err := dm.Flatten()
			if err != nil {
				o.LogError("flattening DNS message failed: %e", err)
				continue
			}
			json.NewEncoder(o.transportWriter).Encode(flat)
			o.transportWriter.WriteString(o.config.Loggers.TcpClient.PayloadDelimiter)
		}

		// flush the transport buffer
		err := o.transportWriter.Flush()
		if err != nil {
			o.LogError("send frame error", err.Error())
			o.writerReady = false
			<-o.transportReconnect
			break
		}
	}

	// reset buffer
	*buf = nil
}

func (o *TcpClient) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.outputChan)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go o.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-o.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			o.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-o.configChan:
			if !opened {
				return
			}
			o.config = cfg
			o.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-o.inputChan:
			if !opened {
				o.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDnsMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// send to output channel
			o.outputChan <- dm
		}
	}
	o.LogInfo("run terminated")
}

func (o *TcpClient) Process() {
	// init buffer
	bufferDm := []dnsutils.DnsMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(o.config.Loggers.TcpClient.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// init remote conn
	go o.ConnectToRemote()

	o.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			// closing remote connection if exist
			o.Disconnect()
			o.doneProcess <- true
			break PROCESS_LOOP

		case <-o.transportReady:
			o.LogInfo("transport connected with success")
			o.transportWriter = bufio.NewWriter(o.transportConn)
			o.writerReady = true

		// incoming dns message to process
		case dm, opened := <-o.outputChan:
			if !opened {
				o.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !o.writerReady {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= o.config.Loggers.TcpClient.BufferSize {
				o.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !o.writerReady {
				o.LogInfo("buffer cleared!")
				bufferDm = nil
				continue
			}

			if len(bufferDm) > 0 {
				o.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)

		}
	}
	o.LogInfo("processing terminated")
}
