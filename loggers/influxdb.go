package loggers

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
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
	inputChan    chan dnsutils.DNSMessage
	outputChan   chan dnsutils.DNSMessage
	config       *pkgconfig.Config
	configChan   chan *pkgconfig.Config
	logger       *logger.Logger
	influxdbConn influxdb2.Client
	writeAPI     api.WriteAPI
	name         string
}

func NewInfluxDBClient(config *pkgconfig.Config, logger *logger.Logger, name string) *InfluxDBClient {
	logger.Info("[%s] logger=influxdb - enabled", name)

	s := &InfluxDBClient{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DNSMessage, config.Loggers.InfluxDB.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DNSMessage, config.Loggers.InfluxDB.ChannelBufferSize),
		logger:      logger,
		config:      config,
		configChan:  make(chan *pkgconfig.Config),
		name:        name,
	}

	s.ReadConfig()

	return s
}

func (i *InfluxDBClient) GetName() string { return i.name }

func (c *InfluxDBClient) AddDroppedRoute(wrk dnsutils.Worker) {}

func (i *InfluxDBClient) AddDefaultRoute(wrk dnsutils.Worker) {}

func (i *InfluxDBClient) SetLoggers(loggers []dnsutils.Worker) {}

func (i *InfluxDBClient) ReadConfig() {}

func (i *InfluxDBClient) ReloadConfig(config *pkgconfig.Config) {
	i.LogInfo("reload configuration!")
	i.configChan <- config
}

func (i *InfluxDBClient) LogInfo(msg string, v ...interface{}) {
	i.logger.Info("["+i.name+"] logger=influxdb - "+msg, v...)
}

func (i *InfluxDBClient) LogError(msg string, v ...interface{}) {
	i.logger.Error("["+i.name+"] logger=influxdb - "+msg, v...)
}

func (i *InfluxDBClient) Channel() chan dnsutils.DNSMessage {
	return i.inputChan
}

func (i *InfluxDBClient) Stop() {
	i.LogInfo("stopping to run...")
	i.stopRun <- true
	<-i.doneRun

	i.LogInfo("stopping to process...")
	i.stopProcess <- true
	<-i.doneProcess
}

func (i *InfluxDBClient) Run() {
	i.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, i.outputChan)
	subprocessors := transformers.NewTransforms(&i.config.OutgoingTransformers, i.logger, i.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go i.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-i.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			i.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-i.configChan:
			if !opened {
				return
			}
			i.config = cfg
			i.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-i.inputChan:
			if !opened {
				i.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// send to output channel
			i.outputChan <- dm
		}
	}
	i.LogInfo("run terminated")
}

func (i *InfluxDBClient) Process() {
	// prepare options for influxdb
	opts := influxdb2.DefaultOptions()
	opts.SetUseGZip(true)
	if i.config.Loggers.InfluxDB.TLSSupport {
		tlsOptions := pkgconfig.TLSOptions{
			InsecureSkipVerify: i.config.Loggers.InfluxDB.TLSInsecure,
			MinVersion:         i.config.Loggers.InfluxDB.TLSMinVersion,
			CAFile:             i.config.Loggers.InfluxDB.CAFile,
			CertFile:           i.config.Loggers.InfluxDB.CertFile,
			KeyFile:            i.config.Loggers.InfluxDB.KeyFile,
		}

		tlsConfig, err := pkgconfig.TLSClientConfig(tlsOptions)
		if err != nil {
			i.logger.Fatal("logger=influxdb - tls config failed:", err)
		}

		opts.SetTLSConfig(tlsConfig)
	}
	// init the client
	influxClient := influxdb2.NewClientWithOptions(
		i.config.Loggers.InfluxDB.ServerURL,
		i.config.Loggers.InfluxDB.AuthToken,
		opts,
	)

	writeAPI := influxClient.WriteAPI(
		i.config.Loggers.InfluxDB.Organization,
		i.config.Loggers.InfluxDB.Bucket,
	)

	i.influxdbConn = influxClient
	i.writeAPI = writeAPI

	i.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-i.stopProcess:
			// Force all unwritten data to be sent
			i.writeAPI.Flush()
			// Ensures background processes finishes
			i.influxdbConn.Close()
			i.doneProcess <- true
			break PROCESS_LOOP
		// incoming dns message to process
		case dm, opened := <-i.outputChan:
			if !opened {
				i.LogInfo("output channel closed!")
				return
			}

			p := influxdb2.NewPointWithMeasurement("dns").
				AddTag("Identity", dm.DNSTap.Identity).
				AddTag("QueryIP", dm.NetworkInfo.QueryIP).
				AddTag("Qname", dm.DNS.Qname).
				AddField("Operation", dm.DNSTap.Operation).
				AddField("Family", dm.NetworkInfo.Family).
				AddField("Protocol", dm.NetworkInfo.Protocol).
				AddField("Qtype", dm.DNS.Qtype).
				AddField("Rcode", dm.DNS.Rcode).
				SetTime(time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec)))

			// write asynchronously
			i.writeAPI.WritePoint(p)
		}
	}
	i.LogInfo("processing terminated")
}
