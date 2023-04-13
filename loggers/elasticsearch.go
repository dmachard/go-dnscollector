package loggers

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"

	"net/http"
)

type ElasticSearchClient struct {
	done    chan bool
	channel chan dnsutils.DnsMessage
	config  *dnsutils.Config
	logger  *logger.Logger
	name    string
	url     string
}

func NewElasticSearchClient(config *dnsutils.Config, console *logger.Logger, name string) *ElasticSearchClient {
	console.Info("[%s] logger elasticsearch - enabled", name)
	o := &ElasticSearchClient{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  console,
		config:  config,
		name:    name,
	}
	o.ReadConfig()
	return o
}

func (c *ElasticSearchClient) GetName() string { return c.name }

func (c *ElasticSearchClient) SetLoggers(loggers []dnsutils.Worker) {}

func (c *ElasticSearchClient) ReadConfig() {
	c.url = c.config.Loggers.ElasticSearchClient.URL
}

func (o *ElasticSearchClient) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *ElasticSearchClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to elasticsearch - "+msg, v...)
}

func (o *ElasticSearchClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to elasticsearch - "+msg, v...)
}

func (o *ElasticSearchClient) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *ElasticSearchClient) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.channel)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel)

	for dm := range o.channel {
		// apply tranforms
		if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
			continue
		}

		buffer := new(bytes.Buffer)
		flat, err := dm.Flatten()
		if err != nil {
			o.LogError("flattening DNS message failed: %e", err)
		}
		json.NewEncoder(buffer).Encode(flat)

		req, _ := http.NewRequest("POST", o.url, buffer)
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		_, err = client.Do(req)
		if err != nil {
			o.LogError(err.Error())
		}

		//
		buffer.Reset()

	}

	o.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	o.done <- true
}
