package loggers

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapSender struct {
	stopProcess        chan bool
	doneProcess        chan bool
	stopRun            chan bool
	doneRun            chan bool
	inputChan          chan dnsutils.DNSMessage
	outputChan         chan dnsutils.DNSMessage
	config             *pkgconfig.Config
	configChan         chan *pkgconfig.Config
	logger             *logger.Logger
	fs                 *framestream.Fstrm
	fsReady            bool
	transport          string
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	name               string
	RoutingHandler     pkgutils.RoutingHandler
}

func NewDnstapSender(config *pkgconfig.Config, logger *logger.Logger, name string) *DnstapSender {
	logger.Info("[%s] logger=dnstap - enabled", name)
	ds := &DnstapSender{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		inputChan:          make(chan dnsutils.DNSMessage, config.Loggers.DNSTap.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DNSMessage, config.Loggers.DNSTap.ChannelBufferSize),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             logger,
		config:             config,
		configChan:         make(chan *pkgconfig.Config),
		name:               name,
		RoutingHandler:     pkgutils.NewRoutingHandler(config, logger, name),
	}

	ds.ReadConfig()
	return ds
}

func (ds *DnstapSender) GetName() string { return ds.name }

func (ds *DnstapSender) AddDroppedRoute(wrk pkgutils.Worker) {
	ds.RoutingHandler.AddDroppedRoute(wrk)
}

func (ds *DnstapSender) AddDefaultRoute(wrk pkgutils.Worker) {
	ds.RoutingHandler.AddDefaultRoute(wrk)
}

func (ds *DnstapSender) SetLoggers(loggers []pkgutils.Worker) {}

func (ds *DnstapSender) ReadConfig() {
	ds.transport = ds.config.Loggers.DNSTap.Transport

	// begin backward compatibility
	if ds.config.Loggers.DNSTap.TLSSupport {
		ds.transport = netlib.SocketTLS
	}
	if len(ds.config.Loggers.DNSTap.SockPath) > 0 {
		ds.transport = netlib.SocketUnix
	}
	// end

	// get hostname or global one
	if ds.config.Loggers.DNSTap.ServerID == "" {
		ds.config.Loggers.DNSTap.ServerID = ds.config.GetServerIdentity()
	}

	if !pkgconfig.IsValidTLS(ds.config.Loggers.DNSTap.TLSMinVersion) {
		ds.logger.Fatal("logger=dnstap - invalid tls min version")
	}
}

func (ds *DnstapSender) ReloadConfig(config *pkgconfig.Config) {
	ds.LogInfo("reload configuration!")
	ds.configChan <- config
}

func (ds *DnstapSender) LogInfo(msg string, v ...interface{}) {
	ds.logger.Info("["+ds.name+"] logger=dnstap - "+msg, v...)
}

func (ds *DnstapSender) LogError(msg string, v ...interface{}) {
	ds.logger.Error("["+ds.name+"] logger=dnstap - "+msg, v...)
}

func (ds *DnstapSender) GetInputChannel() chan dnsutils.DNSMessage {
	return ds.inputChan
}

func (ds *DnstapSender) Stop() {
	ds.LogInfo("stopping routing handler...")
	ds.RoutingHandler.Stop()

	ds.LogInfo("stopping to run...")
	ds.stopRun <- true
	<-ds.doneRun

	ds.LogInfo("stopping to process...")
	ds.stopProcess <- true
	<-ds.doneProcess
}

func (ds *DnstapSender) Disconnect() {
	if ds.transportConn != nil {
		// reset framestream and ignore errors
		ds.LogInfo("closing framestream")
		ds.fs.ResetSender()

		// closing tcp
		ds.LogInfo("closing tcp connection")
		ds.transportConn.Close()
		ds.LogInfo("closed")
	}
}

func (ds *DnstapSender) ConnectToRemote() {
	for {
		if ds.transportConn != nil {
			ds.transportConn.Close()
			ds.transportConn = nil
		}

		address := net.JoinHostPort(
			ds.config.Loggers.DNSTap.RemoteAddress,
			strconv.Itoa(ds.config.Loggers.DNSTap.RemotePort),
		)
		connTimeout := time.Duration(ds.config.Loggers.DNSTap.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch ds.transport {
		case netlib.SocketUnix:
			address = ds.config.Loggers.DNSTap.RemoteAddress
			if len(ds.config.Loggers.DNSTap.SockPath) > 0 {
				address = ds.config.Loggers.DNSTap.SockPath
			}
			ds.LogInfo("connecting to %s://%s", ds.transport, address)
			conn, err = net.DialTimeout(ds.transport, address, connTimeout)

		case netlib.SocketTCP:
			ds.LogInfo("connecting to %s://%s", ds.transport, address)
			conn, err = net.DialTimeout(ds.transport, address, connTimeout)

		case netlib.SocketTLS:
			ds.LogInfo("connecting to %s://%s", ds.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := pkgconfig.TLSOptions{
				InsecureSkipVerify: ds.config.Loggers.DNSTap.TLSInsecure,
				MinVersion:         ds.config.Loggers.DNSTap.TLSMinVersion,
				CAFile:             ds.config.Loggers.DNSTap.CAFile,
				CertFile:           ds.config.Loggers.DNSTap.CertFile,
				KeyFile:            ds.config.Loggers.DNSTap.KeyFile,
			}

			tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netlib.SocketTCP, address, tlsConfig)
			}
		default:
			ds.logger.Fatal("logger=dnstap - invalid transport:", ds.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			ds.LogError("%s", err)
			ds.LogInfo("retry to connect in %d seconds", ds.config.Loggers.DNSTap.RetryInterval)
			time.Sleep(time.Duration(ds.config.Loggers.DNSTap.RetryInterval) * time.Second)
			continue
		}

		ds.transportConn = conn

		// block until framestream is ready
		ds.transportReady <- true

		// block until an error occured, need to reconnect
		ds.transportReconnect <- true
	}
}

func (ds *DnstapSender) FlushBuffer(buf *[]dnsutils.DNSMessage) {

	var data []byte
	var err error
	frame := &framestream.Frame{}

	for _, dm := range *buf {
		// update identity ?
		if ds.config.Loggers.DNSTap.OverwriteIdentity {
			dm.DNSTap.Identity = ds.config.Loggers.DNSTap.ServerID
		}

		// encode dns message to dnstap protobuf binary
		data, err = dm.ToDNSTap()
		if err != nil {
			ds.LogError("failed to encode to DNStap protobuf: %s", err)
			continue
		}

		// send the frame
		frame.Write(data)
		if err := ds.fs.SendFrame(frame); err != nil {
			ds.LogError("send frame error %s", err)
			ds.fsReady = false
			<-ds.transportReconnect
			break
		}
	}

	// reset buffer
	*buf = nil
}

func (ds *DnstapSender) Run() {
	ds.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := ds.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := ds.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, ds.outputChan)
	subprocessors := transformers.NewTransforms(&ds.config.OutgoingTransformers, ds.logger, ds.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go ds.Process()

	// init remote conn
	go ds.ConnectToRemote()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-ds.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			ds.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-ds.configChan:
			if !opened {
				return
			}
			ds.config = cfg
			ds.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-ds.inputChan:
			if !opened {
				ds.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				ds.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			ds.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			ds.outputChan <- dm
		}
	}
	ds.LogInfo("run terminated")
}

func (ds *DnstapSender) Process() {
	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(ds.config.Loggers.DNSTap.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// nextStanzaBufferInterval := 10 * time.Second
	// nextStanzaBufferFull := time.NewTimer(nextStanzaBufferInterval)

	ds.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-ds.stopProcess:
			// closing remote connection if exist
			ds.Disconnect()

			ds.doneProcess <- true
			break PROCESS_LOOP

		// case stanzaName := <-ds.dropped:
		// 	if _, ok := ds.droppedCount[stanzaName]; !ok {
		// 		ds.droppedCount[stanzaName] = 1
		// 	} else {
		// 		ds.droppedCount[stanzaName]++
		// 	}

		// init framestream
		case <-ds.transportReady:
			ds.LogInfo("transport connected with success")
			// frame stream library
			r := bufio.NewReader(ds.transportConn)
			w := bufio.NewWriter(ds.transportConn)
			ds.fs = framestream.NewFstrm(r, w, ds.transportConn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

			// init framestream protocol
			if err := ds.fs.InitSender(); err != nil {
				ds.LogError("sender protocol initialization error %s", err)
				ds.fsReady = false
				ds.transportConn.Close()
				<-ds.transportReconnect
			} else {
				ds.fsReady = true
				ds.LogInfo("framestream initialized with success")
			}
		// incoming dns message to process
		case dm, opened := <-ds.outputChan:
			if !opened {
				ds.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !ds.fsReady {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= ds.config.Loggers.DNSTap.BufferSize {
				ds.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			// force to flush the buffer
			if len(bufferDm) > 0 {
				ds.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)

			// case <-nextStanzaBufferFull.C:
			// 	for v, k := range ds.droppedCount {
			// 		if k > 0 {
			// 			ds.LogError("stanza[%s] buffer is full, %d packet(s) dropped", v, k)
			// 			ds.droppedCount[v] = 0
			// 		}
			// 	}
			// 	nextStanzaBufferFull.Reset(nextStanzaBufferInterval)
		}
	}
	ds.LogInfo("processing terminated")
}
