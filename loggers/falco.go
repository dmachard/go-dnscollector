package loggers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type FalcoClient struct {
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
	url            string
	RoutingHandler pkgutils.RoutingHandler
}

func NewFalcoClient(config *pkgconfig.Config, console *logger.Logger, name string) *FalcoClient {
	console.Info("[%s] logger=falco - enabled", name)
	fc := &FalcoClient{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.FalcoClient.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.FalcoClient.ChannelBufferSize),
		logger:         console,
		config:         config,
		configChan:     make(chan *pkgconfig.Config),
		name:           name,
		RoutingHandler: pkgutils.NewRoutingHandler(config, console, name),
	}
	fc.ReadConfig()
	return fc
}

func (fc *FalcoClient) GetName() string { return fc.name }

func (fc *FalcoClient) AddDroppedRoute(wrk pkgutils.Worker) {}

func (fc *FalcoClient) AddDefaultRoute(wrk pkgutils.Worker) {}

func (fc *FalcoClient) SetLoggers(loggers []pkgutils.Worker) {}

func (fc *FalcoClient) ReadConfig() {
	fc.url = fc.config.Loggers.FalcoClient.URL
}

func (fc *FalcoClient) ReloadConfig(config *pkgconfig.Config) {
	fc.LogInfo("reload configuration!")
	fc.configChan <- config
}

func (fc *FalcoClient) GetInputChannel() chan dnsutils.DNSMessage {
	return fc.inputChan
}

func (fc *FalcoClient) LogInfo(msg string, v ...interface{}) {
	fc.logger.Info("["+fc.name+"] logger=falco - "+msg, v...)
}

func (fc *FalcoClient) LogError(msg string, v ...interface{}) {
	fc.logger.Error("["+fc.name+"] logger=falco - "+msg, v...)
}

func (fc *FalcoClient) Stop() {
	fc.LogInfo("stopping routing handler...")
	fc.RoutingHandler.Stop()

	fc.LogInfo("stopping to run...")
	fc.stopRun <- true
	<-fc.doneRun

	fc.LogInfo("stopping to process...")
	fc.stopProcess <- true
	<-fc.doneProcess
}

func (fc *FalcoClient) Run() {
	fc.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, fc.outputChan)
	subprocessors := transformers.NewTransforms(&fc.config.OutgoingTransformers, fc.logger, fc.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go fc.Process()

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
				continue
			}

			// send to output channel
			fc.outputChan <- dm
		}
	}
	fc.LogInfo("run terminated")
}

func (fc *FalcoClient) Process() {
	buffer := new(bytes.Buffer)
	fc.LogInfo("ready to process")

PROCESS_LOOP:
	for {
		select {
		case <-fc.stopProcess:
			fc.doneProcess <- true
			break PROCESS_LOOP

			// incoming dns message to process
		case dm, opened := <-fc.outputChan:
			if !opened {
				fc.LogInfo("output channel closed!")
				return
			}

			// encode
			json.NewEncoder(buffer).Encode(dm)

			req, _ := http.NewRequest("POST", fc.url, buffer)
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			_, err := client.Do(req)
			if err != nil {
				fc.LogError(err.Error())
			}

			// finally reset the buffer for next iter
			buffer.Reset()
		}
	}
	fc.LogInfo("processing terminated")
}
