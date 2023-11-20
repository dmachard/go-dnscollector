package loggers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type FalcoClient struct {
	stopProcess chan bool
	doneProcess chan bool
	stopRun     chan bool
	doneRun     chan bool
	inputChan   chan dnsutils.DNSMessage
	outputChan  chan dnsutils.DNSMessage
	config      *dnsutils.Config
	configChan  chan *dnsutils.Config
	logger      *logger.Logger
	name        string
	url         string
}

func NewFalcoClient(config *dnsutils.Config, console *logger.Logger, name string) *FalcoClient {
	console.Info("[%s] logger=falco - enabled", name)
	f := &FalcoClient{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DNSMessage, config.Loggers.FalcoClient.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DNSMessage, config.Loggers.FalcoClient.ChannelBufferSize),
		logger:      console,
		config:      config,
		configChan:  make(chan *dnsutils.Config),
		name:        name,
	}
	f.ReadConfig()
	return f
}

func (f *FalcoClient) GetName() string { return f.name }

func (f *FalcoClient) SetLoggers(loggers []dnsutils.Worker) {}

func (f *FalcoClient) ReadConfig() {
	f.url = f.config.Loggers.FalcoClient.URL
}

func (f *FalcoClient) ReloadConfig(config *dnsutils.Config) {
	f.LogInfo("reload configuration!")
	f.configChan <- config
}

func (f *FalcoClient) Channel() chan dnsutils.DNSMessage {
	return f.inputChan
}

func (f *FalcoClient) LogInfo(msg string, v ...interface{}) {
	f.logger.Info("["+f.name+"] logger=falco - "+msg, v...)
}

func (f *FalcoClient) LogError(msg string, v ...interface{}) {
	f.logger.Error("["+f.name+"] logger=falco - "+msg, v...)
}

func (f *FalcoClient) Stop() {
	f.LogInfo("stopping to run...")
	f.stopRun <- true
	<-f.doneRun

	f.LogInfo("stopping to process...")
	f.stopProcess <- true
	<-f.doneProcess
}

func (f *FalcoClient) Run() {
	f.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, f.outputChan)
	subprocessors := transformers.NewTransforms(&f.config.OutgoingTransformers, f.logger, f.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go f.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-f.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			f.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-f.configChan:
			if !opened {
				return
			}
			f.config = cfg
			f.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-f.inputChan:
			if !opened {
				f.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// send to output channel
			f.outputChan <- dm
		}
	}
	f.LogInfo("run terminated")
}

func (f *FalcoClient) Process() {
	buffer := new(bytes.Buffer)
	f.LogInfo("ready to process")

PROCESS_LOOP:
	for {
		select {
		case <-f.stopProcess:
			f.doneProcess <- true
			break PROCESS_LOOP

			// incoming dns message to process
		case dm, opened := <-f.outputChan:
			if !opened {
				f.LogInfo("output channel closed!")
				return
			}

			// encode
			json.NewEncoder(buffer).Encode(dm)

			req, _ := http.NewRequest("POST", f.url, buffer)
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			_, err := client.Do(req)
			if err != nil {
				f.LogError(err.Error())
			}

			// finally reset the buffer for next iter
			buffer.Reset()
		}
	}
	f.LogInfo("processing terminated")
}
