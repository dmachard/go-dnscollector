package loggers

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/vmihailenco/msgpack"
)

type FluentdClient struct {
	stopProcess        chan bool
	doneProcess        chan bool
	stopRun            chan bool
	doneRun            chan bool
	inputChan          chan dnsutils.DnsMessage
	outputChan         chan dnsutils.DnsMessage
	config             *dnsutils.Config
	configChan         chan *dnsutils.Config
	logger             *logger.Logger
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	writerReady        bool
	name               string
}

func NewFluentdClient(config *dnsutils.Config, logger *logger.Logger, name string) *FluentdClient {
	logger.Info("[%s] logger=fluentd - enabled", name)
	s := &FluentdClient{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		inputChan:          make(chan dnsutils.DnsMessage, config.Loggers.Fluentd.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DnsMessage, config.Loggers.Fluentd.ChannelBufferSize),
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

func (c *FluentdClient) GetName() string { return c.name }

func (c *FluentdClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *FluentdClient) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.Fluentd.TlsMinVersion) {
		o.logger.Fatal("logger=fluentd - invalid tls min version")
	}
}

func (o *FluentdClient) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload configuration!")
	o.configChan <- config
}

func (o *FluentdClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger=fluentd - "+msg, v...)
}

func (o *FluentdClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger=fluentd - "+msg, v...)
}

func (o *FluentdClient) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *FluentdClient) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *FluentdClient) Disconnect() {
	if o.transportConn != nil {
		o.LogInfo("closing tcp connection")
		o.transportConn.Close()
	}
}

func (o *FluentdClient) ConnectToRemote() {
	// prepare the address
	var address string
	if len(o.config.Loggers.Fluentd.SockPath) > 0 {
		address = o.config.Loggers.Fluentd.SockPath
	} else {
		address = o.config.Loggers.Fluentd.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.Fluentd.RemotePort)
	}

	connTimeout := time.Duration(o.config.Loggers.Dnstap.ConnectTimeout) * time.Second

	// make the connection
	for {
		if o.transportConn != nil {
			o.transportConn.Close()
			o.transportConn = nil
		}

		// make the connection
		o.LogInfo("connecting to %s", address)
		//var conn net.Conn
		var err error
		if o.config.Loggers.Fluentd.TlsSupport {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			}

			tlsConfig.InsecureSkipVerify = o.config.Loggers.Fluentd.TlsInsecure
			tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.Fluentd.TlsMinVersion]

			dialer := &net.Dialer{Timeout: connTimeout}
			o.transportConn, err = tls.DialWithDialer(dialer, o.config.Loggers.Fluentd.Transport, address, tlsConfig)
		} else {
			o.transportConn, err = net.DialTimeout(o.config.Loggers.Fluentd.Transport, address, connTimeout)
		}

		// something is wrong during connection ?
		if err != nil {
			o.LogError("connect error: %s", err)
			o.LogInfo("retry to connect in %d seconds", o.config.Loggers.Fluentd.RetryInterval)
			time.Sleep(time.Duration(o.config.Loggers.Fluentd.RetryInterval) * time.Second)
			continue
		}

		// block until framestream is ready
		o.transportReady <- true

		// block until an error occured, need to reconnect
		o.transportReconnect <- true
	}
}

func (o *FluentdClient) FlushBuffer(buf *[]dnsutils.DnsMessage) {

	tag, _ := msgpack.Marshal(o.config.Loggers.Fluentd.Tag)

	for _, dm := range *buf {
		// prepare event
		tm, _ := msgpack.Marshal(dm.DnsTap.TimeSec)
		record, err := msgpack.Marshal(dm)
		if err != nil {
			o.LogError("msgpack error:", err.Error())
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
		_, err = o.transportConn.Write(encoded)

		// flusth the buffer
		if err != nil {
			o.LogError("send transport error", err.Error())
			o.writerReady = false
			<-o.transportReconnect
			break
		}
	}
}

func (o *FluentdClient) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.outputChan)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go o.Process()

	// init remote conn
	go o.ConnectToRemote()

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

func (o *FluentdClient) Process() {
	// init buffer
	bufferDm := []dnsutils.DnsMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(o.config.Loggers.Fluentd.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	o.LogInfo("ready to process")

PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			o.doneProcess <- true
			break PROCESS_LOOP

		case <-o.transportReady:
			o.LogInfo("connected")
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
			if len(bufferDm) >= o.config.Loggers.Fluentd.BufferSize {
				o.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !o.writerReady {
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
