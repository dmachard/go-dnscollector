package loggers

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/vmihailenco/msgpack"
)

type FluentdClient struct {
	stopProcess        chan bool
	doneProcess        chan bool
	stopRun            chan bool
	doneRun            chan bool
	stopRead           chan bool
	doneRead           chan bool
	inputChan          chan dnsutils.DNSMessage
	outputChan         chan dnsutils.DNSMessage
	config             *pkgconfig.Config
	configChan         chan *pkgconfig.Config
	logger             *logger.Logger
	transport          string
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	writerReady        bool
	name               string
	RoutingHandler     pkgutils.RoutingHandler
}

func NewFluentdClient(config *pkgconfig.Config, logger *logger.Logger, name string) *FluentdClient {
	logger.Info("[%s] logger=fluentd - enabled", name)
	fc := &FluentdClient{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		stopRead:           make(chan bool),
		doneRead:           make(chan bool),
		inputChan:          make(chan dnsutils.DNSMessage, config.Loggers.Fluentd.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DNSMessage, config.Loggers.Fluentd.ChannelBufferSize),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             logger,
		config:             config,
		configChan:         make(chan *pkgconfig.Config),
		name:               name,
		RoutingHandler:     pkgutils.NewRoutingHandler(config, logger, name),
	}

	fc.ReadConfig()
	return fc
}

func (fc *FluentdClient) GetName() string { return fc.name }

func (fc *FluentdClient) AddDroppedRoute(wrk pkgutils.Worker) {
	fc.RoutingHandler.AddDroppedRoute(wrk)
}

func (fc *FluentdClient) AddDefaultRoute(wrk pkgutils.Worker) {
	fc.RoutingHandler.AddDefaultRoute(wrk)
}

func (fc *FluentdClient) SetLoggers(loggers []pkgutils.Worker) {}

func (fc *FluentdClient) ReadConfig() {
	fc.transport = fc.config.Loggers.Fluentd.Transport

	// begin backward compatibility
	if fc.config.Loggers.Fluentd.TLSSupport {
		fc.transport = netlib.SocketTLS
	}
	if len(fc.config.Loggers.Fluentd.SockPath) > 0 {
		fc.transport = netlib.SocketUnix
	}
}

func (fc *FluentdClient) ReloadConfig(config *pkgconfig.Config) {
	fc.LogInfo("reload configuration!")
	fc.configChan <- config
}

func (fc *FluentdClient) LogInfo(msg string, v ...interface{}) {
	fc.logger.Info("["+fc.name+"] logger=fluentd - "+msg, v...)
}

func (fc *FluentdClient) LogError(msg string, v ...interface{}) {
	fc.logger.Error("["+fc.name+"] logger=fluentd - "+msg, v...)
}

func (fc *FluentdClient) GetInputChannel() chan dnsutils.DNSMessage {
	return fc.inputChan
}

func (fc *FluentdClient) Stop() {
	fc.LogInfo("stopping routing handler...")
	fc.RoutingHandler.Stop()

	fc.LogInfo("stopping to run...")
	fc.stopRun <- true
	<-fc.doneRun

	fc.LogInfo("stopping to read...")
	fc.stopRead <- true
	<-fc.doneRead

	fc.LogInfo("stopping to process...")
	fc.stopProcess <- true
	<-fc.doneProcess
}

func (fc *FluentdClient) Disconnect() {
	if fc.transportConn != nil {
		fc.LogInfo("closing tcp connection")
		fc.transportConn.Close()
	}
}

func (fc *FluentdClient) ReadFromConnection() {
	buffer := make([]byte, 4096)

	go func() {
		for {
			_, err := fc.transportConn.Read(buffer)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					fc.LogInfo("read from connection terminated")
					break
				}
				fc.LogError("Error on reading: %s", err.Error())
			}
			// We just discard the data
		}
	}()

	// block goroutine until receive true event in stopRead channel
	<-fc.stopRead
	fc.doneRead <- true

	fc.LogInfo("read goroutine terminated")
}

func (fc *FluentdClient) ConnectToRemote() {
	for {
		if fc.transportConn != nil {
			fc.transportConn.Close()
			fc.transportConn = nil
		}

		address := fc.config.Loggers.Fluentd.RemoteAddress + ":" + strconv.Itoa(fc.config.Loggers.Fluentd.RemotePort)
		connTimeout := time.Duration(fc.config.Loggers.Fluentd.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch fc.transport {
		case netlib.SocketUnix:
			address = fc.config.Loggers.Fluentd.RemoteAddress
			if len(fc.config.Loggers.Fluentd.SockPath) > 0 {
				address = fc.config.Loggers.Fluentd.SockPath
			}
			fc.LogInfo("connecting to %s://%s", fc.transport, address)
			conn, err = net.DialTimeout(fc.transport, address, connTimeout)

		case netlib.SocketTCP:
			fc.LogInfo("connecting to %s://%s", fc.transport, address)
			conn, err = net.DialTimeout(fc.transport, address, connTimeout)

		case netlib.SocketTLS:
			fc.LogInfo("connecting to %s://%s", fc.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := pkgconfig.TLSOptions{
				InsecureSkipVerify: fc.config.Loggers.Fluentd.TLSInsecure,
				MinVersion:         fc.config.Loggers.Fluentd.TLSMinVersion,
				CAFile:             fc.config.Loggers.Fluentd.CAFile,
				CertFile:           fc.config.Loggers.Fluentd.CertFile,
				KeyFile:            fc.config.Loggers.Fluentd.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netlib.SocketTCP, address, tlsConfig)
			}
		default:
			fc.logger.Fatal("logger=fluent - invalid transport:", fc.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			fc.LogError("connect error: %s", err)
			fc.LogInfo("retry to connect in %d seconds", fc.config.Loggers.Fluentd.RetryInterval)
			time.Sleep(time.Duration(fc.config.Loggers.Fluentd.RetryInterval) * time.Second)
			continue
		}

		fc.transportConn = conn

		// block until framestream is ready
		fc.transportReady <- true

		// block until an error occurred, need to reconnect
		fc.transportReconnect <- true
	}
}

func (fc *FluentdClient) FlushBuffer(buf *[]dnsutils.DNSMessage) {

	tag, _ := msgpack.Marshal(fc.config.Loggers.Fluentd.Tag)

	for _, dm := range *buf {
		// prepare event
		tm, _ := msgpack.Marshal(dm.DNSTap.TimeSec)
		record, err := msgpack.Marshal(dm)
		if err != nil {
			fc.LogError("msgpack error:", err.Error())
			continue
		}

		// Message ::= [ Tag, Time, Record, Option? ]
		encoded := []byte{}
		// array, size 3
		encoded = append(encoded, 0x93)
		// append tag, time and record
		encoded = append(encoded, tag...)
		encoded = append(encoded, tm...)
		encoded = append(encoded, record...)

		// write event message
		_, err = fc.transportConn.Write(encoded)

		// flusth the buffer
		if err != nil {
			fc.LogError("send transport error", err.Error())
			fc.writerReady = false
			<-fc.transportReconnect
			break
		}
	}
}

func (fc *FluentdClient) Run() {
	fc.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := fc.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := fc.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, fc.outputChan)
	subprocessors := transformers.NewTransforms(&fc.config.OutgoingTransformers, fc.logger, fc.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go fc.Process()

	// init remote conn
	go fc.ConnectToRemote()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-fc.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			fc.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-fc.configChan:
			if !opened {
				return
			}
			fc.config = cfg
			fc.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-fc.inputChan:
			if !opened {
				fc.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				fc.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			fc.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			fc.outputChan <- dm
		}
	}
	fc.LogInfo("run terminated")
}

func (fc *FluentdClient) Process() {
	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(fc.config.Loggers.Fluentd.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	fc.LogInfo("ready to process")

PROCESS_LOOP:
	for {
		select {
		case <-fc.stopProcess:
			fc.doneProcess <- true
			break PROCESS_LOOP

		case <-fc.transportReady:
			fc.LogInfo("connected")
			fc.writerReady = true

			// read from the connection until we stop
			go fc.ReadFromConnection()

		// incoming dns message to process
		case dm, opened := <-fc.outputChan:
			if !opened {
				fc.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !fc.writerReady {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= fc.config.Loggers.Fluentd.BufferSize {
				fc.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !fc.writerReady {
				bufferDm = nil
			}

			if len(bufferDm) > 0 {
				fc.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
	fc.LogInfo("processing terminated")
}
