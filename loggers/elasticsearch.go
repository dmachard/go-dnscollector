package loggers

import (
	"bytes"
	"encoding/json"
	"path"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"

	"net/http"
	"net/url"
)

type ElasticSearchClient struct {
	stopProcess chan bool
	doneProcess chan bool
	stopRun     chan bool
	doneRun     chan bool
	inputChan   chan dnsutils.DnsMessage
	outputChan  chan dnsutils.DnsMessage
	config      *dnsutils.Config
	logger      *logger.Logger
	name        string
	server      string
	index       string
	bulkUrl     string
}

func NewElasticSearchClient(config *dnsutils.Config, console *logger.Logger, name string) *ElasticSearchClient {
	console.Info("[%s] logger=elasticsearch - enabled", name)
	o := &ElasticSearchClient{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DnsMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DnsMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		logger:      console,
		config:      config,
		name:        name,
	}
	o.ReadConfig()
	return o
}

func (c *ElasticSearchClient) GetName() string { return c.name }

func (c *ElasticSearchClient) SetLoggers(loggers []dnsutils.Worker) {}

func (c *ElasticSearchClient) ReadConfig() {
	c.server = c.config.Loggers.ElasticSearchClient.Server
	c.index = c.config.Loggers.ElasticSearchClient.Index

	u, err := url.Parse(c.server)
	if err != nil {
		c.LogError(err.Error())
	}
	u.Path = path.Join(u.Path, c.index, "_bulk")
	c.bulkUrl = u.String()
}

func (o *ElasticSearchClient) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload config...")

	// save the new config
	o.config = config

	// read again
	o.ReadConfig()
}

func (o *ElasticSearchClient) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *ElasticSearchClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger=elasticsearch - "+msg, v...)
}

func (o *ElasticSearchClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger=elasticsearch - "+msg, v...)
}

func (o *ElasticSearchClient) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *ElasticSearchClient) Run() {
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

func (o *ElasticSearchClient) FlushBuffer(buf *[]dnsutils.DnsMessage) {
	buffer := new(bytes.Buffer)

	for _, dm := range *buf {
		buffer.WriteString("{ \"create\" : {}}")
		buffer.WriteString("\n")
		// encode
		flat, err := dm.Flatten()
		if err != nil {
			o.LogError("flattening DNS message failed: %e", err)
		}
		json.NewEncoder(buffer).Encode(flat)
	}

	req, _ := http.NewRequest("POST", o.bulkUrl, buffer)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	_, err := client.Do(req)
	if err != nil {
		o.LogError(err.Error())
	}

	*buf = nil
}

func (o *ElasticSearchClient) Process() {
	bufferDm := []dnsutils.DnsMessage{}
	o.LogInfo("ready to process")

	flushInterval := time.Duration(o.config.Loggers.ElasticSearchClient.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			o.doneProcess <- true
			break PROCESS_LOOP

		// incoming dns message to process
		case dm, opened := <-o.outputChan:
			if !opened {
				o.LogInfo("output channel closed!")
				return
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= o.config.Loggers.ElasticSearchClient.BulkSize {
				o.FlushBuffer(&bufferDm)
			}
			// flush the buffer
		case <-flushTimer.C:
			if len(bufferDm) > 0 {
				o.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
	o.LogInfo("processing terminated")
}
