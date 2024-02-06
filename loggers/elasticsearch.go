package loggers

import (
	"bytes"
	"encoding/json"
	"path"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"

	"net/http"
	"net/url"
)

type ElasticSearchClient struct {
	stopProcess    chan bool
	doneProcess    chan bool
	stopRun        chan bool
	doneRun        chan bool
	inputChan      chan dnsutils.DNSMessage
	outputChan     chan dnsutils.DNSMessage
	config         *pkgconfig.Config
	configChan     chan *pkgconfig.Config
	logger         *logger.Logger
	name           string
	server         string
	index          string
	bulkURL        string
	RoutingHandler pkgutils.RoutingHandler
}

func NewElasticSearchClient(config *pkgconfig.Config, console *logger.Logger, name string) *ElasticSearchClient {
	console.Info(pkgutils.PrefixLogLogger+"[%s] elasticsearch - enabled", name)
	ec := &ElasticSearchClient{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		logger:         console,
		config:         config,
		configChan:     make(chan *pkgconfig.Config),
		name:           name,
		RoutingHandler: pkgutils.NewRoutingHandler(config, console, name),
	}
	ec.ReadConfig()
	return ec
}

func (ec *ElasticSearchClient) GetName() string { return ec.name }

func (ec *ElasticSearchClient) AddDroppedRoute(wrk pkgutils.Worker) {
	ec.RoutingHandler.AddDroppedRoute(wrk)
}

func (ec *ElasticSearchClient) AddDefaultRoute(wrk pkgutils.Worker) {
	ec.RoutingHandler.AddDefaultRoute(wrk)
}

func (ec *ElasticSearchClient) SetLoggers(loggers []pkgutils.Worker) {}

func (ec *ElasticSearchClient) ReadConfig() {
	ec.server = ec.config.Loggers.ElasticSearchClient.Server
	ec.index = ec.config.Loggers.ElasticSearchClient.Index

	u, err := url.Parse(ec.server)
	if err != nil {
		ec.LogError(err.Error())
	}
	u.Path = path.Join(u.Path, ec.index, "_bulk")
	ec.bulkURL = u.String()
}

func (ec *ElasticSearchClient) ReloadConfig(config *pkgconfig.Config) {
	ec.LogInfo("reload configuration!")
	ec.configChan <- config
}

func (ec *ElasticSearchClient) GetInputChannel() chan dnsutils.DNSMessage {
	return ec.inputChan
}

func (ec *ElasticSearchClient) LogInfo(msg string, v ...interface{}) {
	ec.logger.Info(pkgutils.PrefixLogLogger+"["+ec.name+"] elasticsearch - "+msg, v...)
}

func (ec *ElasticSearchClient) LogError(msg string, v ...interface{}) {
	ec.logger.Error(pkgutils.PrefixLogLogger+"["+ec.name+"] elasticsearch - "+msg, v...)
}

func (ec *ElasticSearchClient) Stop() {
	ec.LogInfo("stopping logger...")
	ec.RoutingHandler.Stop()

	ec.LogInfo("stopping to run...")
	ec.stopRun <- true
	<-ec.doneRun

	ec.LogInfo("stopping to process...")
	ec.stopProcess <- true
	<-ec.doneProcess
}

func (ec *ElasticSearchClient) Run() {
	ec.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := ec.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := ec.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, ec.outputChan)
	subprocessors := transformers.NewTransforms(&ec.config.OutgoingTransformers, ec.logger, ec.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go ec.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-ec.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			ec.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-ec.configChan:
			if !opened {
				return
			}
			ec.config = cfg
			ec.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-ec.inputChan:
			if !opened {
				ec.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				ec.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			ec.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			ec.outputChan <- dm
		}
	}
	ec.LogInfo("run terminated")
}

func (ec *ElasticSearchClient) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	buffer := new(bytes.Buffer)

	for _, dm := range *buf {
		buffer.WriteString("{ \"create\" : {}}")
		buffer.WriteString("\n")
		// encode
		flat, err := dm.Flatten()
		if err != nil {
			ec.LogError("flattening DNS message failed: %e", err)
		}
		json.NewEncoder(buffer).Encode(flat)
	}

	req, _ := http.NewRequest("POST", ec.bulkURL, buffer)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	_, err := client.Do(req)
	if err != nil {
		ec.LogError(err.Error())
	}

	*buf = nil
}

func (ec *ElasticSearchClient) Process() {
	bufferDm := []dnsutils.DNSMessage{}
	ec.LogInfo("ready to process")

	flushInterval := time.Duration(ec.config.Loggers.ElasticSearchClient.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

PROCESS_LOOP:
	for {
		select {
		case <-ec.stopProcess:
			ec.doneProcess <- true
			break PROCESS_LOOP

		// incoming dns message to process
		case dm, opened := <-ec.outputChan:
			if !opened {
				ec.LogInfo("output channel closed!")
				return
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= ec.config.Loggers.ElasticSearchClient.BulkSize {
				ec.FlushBuffer(&bufferDm)
			}
			// flush the buffer
		case <-flushTimer.C:
			if len(bufferDm) > 0 {
				ec.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
	ec.LogInfo("processing terminated")
}
