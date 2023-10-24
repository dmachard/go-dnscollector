package loggers

import (
	"crypto/tls"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"

	influxdb2 "github.com/influxdata/influxdb-client-go"
	"github.com/influxdata/influxdb-client-go/api"
)

type InfluxDBClient struct {
	stopProcess  chan bool
	doneProcess  chan bool
	stopRun      chan bool
	doneRun      chan bool
	inputChan    chan dnsutils.DnsMessage
	outputChan   chan dnsutils.DnsMessage
	config       *dnsutils.Config
	logger       *logger.Logger
	influxdbConn influxdb2.Client
	writeAPI     api.WriteAPI
	name         string
}

func NewInfluxDBClient(config *dnsutils.Config, logger *logger.Logger, name string) *InfluxDBClient {
	logger.Info("[%s] logger=influxdb - enabled", name)

	s := &InfluxDBClient{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DnsMessage, config.Loggers.InfluxDB.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DnsMessage, config.Loggers.InfluxDB.ChannelBufferSize),
		logger:      logger,
		config:      config,
		name:        name,
	}

	s.ReadConfig()

	return s
}

func (c *InfluxDBClient) GetName() string { return c.name }

func (c *InfluxDBClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *InfluxDBClient) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.InfluxDB.TlsMinVersion) {
		o.logger.Fatal("logger=influxdb - invalid tls min version")
	}
}

func (o *InfluxDBClient) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload config...")

	// save the new config
	o.config = config

	// read again
	o.ReadConfig()
}

func (o *InfluxDBClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger=influxdb - "+msg, v...)
}

func (o *InfluxDBClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger=influxdb - "+msg, v...)
}

func (o *InfluxDBClient) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *InfluxDBClient) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *InfluxDBClient) Run() {
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

func (o *InfluxDBClient) Process() {
	// prepare options for influxdb
	opts := influxdb2.DefaultOptions()
	opts.SetUseGZip(true)
	if o.config.Loggers.InfluxDB.TlsSupport {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		}

		tlsConfig.InsecureSkipVerify = o.config.Loggers.InfluxDB.TlsInsecure
		tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.InfluxDB.TlsMinVersion]

		opts.SetTLSConfig(tlsConfig)
	}
	// init the client
	influxClient := influxdb2.NewClientWithOptions(
		o.config.Loggers.InfluxDB.ServerURL,
		o.config.Loggers.InfluxDB.AuthToken,
		opts,
	)

	writeAPI := influxClient.WriteAPI(
		o.config.Loggers.InfluxDB.Organization,
		o.config.Loggers.InfluxDB.Bucket,
	)

	o.influxdbConn = influxClient
	o.writeAPI = writeAPI

	o.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			// Force all unwritten data to be sent
			o.writeAPI.Flush()
			// Ensures background processes finishes
			o.influxdbConn.Close()
			o.doneProcess <- true
			break PROCESS_LOOP
		// incoming dns message to process
		case dm, opened := <-o.outputChan:
			if !opened {
				o.LogInfo("output channel closed!")
				return
			}

			p := influxdb2.NewPointWithMeasurement("dns").
				AddTag("Identity", dm.DnsTap.Identity).
				AddTag("QueryIP", dm.NetworkInfo.QueryIp).
				AddTag("Qname", dm.DNS.Qname).
				AddField("Operation", dm.DnsTap.Operation).
				AddField("Family", dm.NetworkInfo.Family).
				AddField("Protocol", dm.NetworkInfo.Protocol).
				AddField("Qtype", dm.DNS.Qtype).
				AddField("Rcode", dm.DNS.Rcode).
				SetTime(time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec)))

			// write asynchronously
			o.writeAPI.WritePoint(p)
		}
	}
	o.LogInfo("processing terminated")
}
