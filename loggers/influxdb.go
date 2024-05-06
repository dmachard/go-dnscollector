package loggers

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"

	influxdb2 "github.com/influxdata/influxdb-client-go"
	"github.com/influxdata/influxdb-client-go/api"
)

type InfluxDBClient struct {
	stopProcess, doneProcess chan bool
	stopRun, doneRun         chan bool
	inputChan, outputChan    chan dnsutils.DNSMessage
	config                   *pkgconfig.Config
	configChan               chan *pkgconfig.Config
	logger                   *logger.Logger
	influxdbConn             influxdb2.Client
	writeAPI                 api.WriteAPI
	name                     string
	RoutingHandler           pkgutils.RoutingHandler
}

func NewInfluxDBClient(config *pkgconfig.Config, logger *logger.Logger, name string) *InfluxDBClient {
	logger.Info(pkgutils.PrefixLogLogger+"[%s] influxdb - enabled", name)

	ic := &InfluxDBClient{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.InfluxDB.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.InfluxDB.ChannelBufferSize),
		logger:         logger,
		config:         config,
		configChan:     make(chan *pkgconfig.Config),
		name:           name,
		RoutingHandler: pkgutils.NewRoutingHandler(config, logger, name),
	}

	ic.ReadConfig()

	return ic
}

func (ic *InfluxDBClient) GetName() string { return ic.name }

func (ic *InfluxDBClient) AddDroppedRoute(wrk pkgutils.Worker) {
	ic.RoutingHandler.AddDroppedRoute(wrk)
}

func (ic *InfluxDBClient) AddDefaultRoute(wrk pkgutils.Worker) {
	ic.RoutingHandler.AddDefaultRoute(wrk)
}

func (ic *InfluxDBClient) SetLoggers(loggers []pkgutils.Worker) {}

func (ic *InfluxDBClient) ReadConfig() {}

func (ic *InfluxDBClient) ReloadConfig(config *pkgconfig.Config) {
	ic.LogInfo("reload configuration!")
	ic.configChan <- config
}

func (ic *InfluxDBClient) LogInfo(msg string, v ...interface{}) {
	ic.logger.Info(pkgutils.PrefixLogLogger+"["+ic.name+"] influxdb - "+msg, v...)
}

func (ic *InfluxDBClient) LogError(msg string, v ...interface{}) {
	ic.logger.Error(pkgutils.PrefixLogLogger+"["+ic.name+"] influxdb - "+msg, v...)
}

func (ic *InfluxDBClient) GetInputChannel() chan dnsutils.DNSMessage {
	return ic.inputChan
}

func (ic *InfluxDBClient) Stop() {
	ic.LogInfo("stopping logger...")
	ic.RoutingHandler.Stop()

	ic.LogInfo("stopping to run...")
	ic.stopRun <- true
	<-ic.doneRun

	ic.LogInfo("stopping to process...")
	ic.stopProcess <- true
	<-ic.doneProcess
}

func (ic *InfluxDBClient) StartCollect() {
	ic.LogInfo("worker is starting collection")

	// prepare next channels
	defaultRoutes, defaultNames := ic.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := ic.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, ic.outputChan)
	subprocessors := transformers.NewTransforms(&ic.config.OutgoingTransformers, ic.logger, ic.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go ic.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-ic.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			ic.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-ic.configChan:
			if !opened {
				return
			}
			ic.config = cfg
			ic.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-ic.inputChan:
			if !opened {
				ic.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				ic.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			ic.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			ic.outputChan <- dm
		}
	}
	ic.LogInfo("run terminated")
}

func (ic *InfluxDBClient) Process() {
	// prepare options for influxdb
	opts := influxdb2.DefaultOptions()
	opts.SetUseGZip(true)
	if ic.config.Loggers.InfluxDB.TLSSupport {
		tlsOptions := pkgconfig.TLSOptions{
			InsecureSkipVerify: ic.config.Loggers.InfluxDB.TLSInsecure,
			MinVersion:         ic.config.Loggers.InfluxDB.TLSMinVersion,
			CAFile:             ic.config.Loggers.InfluxDB.CAFile,
			CertFile:           ic.config.Loggers.InfluxDB.CertFile,
			KeyFile:            ic.config.Loggers.InfluxDB.KeyFile,
		}

		tlsConfig, err := pkgconfig.TLSClientConfig(tlsOptions)
		if err != nil {
			ic.logger.Fatal("logger=influxdb - tls config failed:", err)
		}

		opts.SetTLSConfig(tlsConfig)
	}
	// init the client
	influxClient := influxdb2.NewClientWithOptions(
		ic.config.Loggers.InfluxDB.ServerURL,
		ic.config.Loggers.InfluxDB.AuthToken,
		opts,
	)

	writeAPI := influxClient.WriteAPI(
		ic.config.Loggers.InfluxDB.Organization,
		ic.config.Loggers.InfluxDB.Bucket,
	)

	ic.influxdbConn = influxClient
	ic.writeAPI = writeAPI

	ic.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-ic.stopProcess:
			// Force all unwritten data to be sent
			ic.writeAPI.Flush()
			// Ensures background processes finishes
			ic.influxdbConn.Close()
			ic.doneProcess <- true
			break PROCESS_LOOP
		// incoming dns message to process
		case dm, opened := <-ic.outputChan:
			if !opened {
				ic.LogInfo("output channel closed!")
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
			ic.writeAPI.WritePoint(p)
		}
	}
	ic.LogInfo("processing terminated")
}
