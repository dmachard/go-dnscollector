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
	done    chan bool
	channel chan dnsutils.DnsMessage
	config  *dnsutils.Config
	logger  *logger.Logger
	name    string
	url     string
}

func NewFalcoClient(config *dnsutils.Config, console *logger.Logger, name string) *FalcoClient {
	console.Info("[%s] logger falco - enabled", name)
	f := &FalcoClient{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  console,
		config:  config,
		name:    name,
	}
	f.ReadConfig()
	return f
}

func (c *FalcoClient) GetName() string { return c.name }

func (c *FalcoClient) SetLoggers(loggers []dnsutils.Worker) {}

func (c *FalcoClient) ReadConfig() {
	c.url = c.config.Loggers.FalcoClient.URL
}

func (f *FalcoClient) Channel() chan dnsutils.DnsMessage {
	return f.channel
}

func (c *FalcoClient) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger to falco - "+msg, v...)
}

func (c *FalcoClient) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger to falco - "+msg, v...)
}

func (f *FalcoClient) Stop() {
	f.LogInfo("stopping...")

	// close output channel
	f.LogInfo("closing channel")
	close(f.channel)

	// read done channel and block until run is terminated
	<-f.done
	close(f.done)
}

func (f *FalcoClient) Run() {
	f.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, f.channel)
	subprocessors := transformers.NewTransforms(&f.config.OutgoingTransformers, f.logger, f.name, listChannel)

	for dm := range f.channel {
		// apply tranforms
		if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
			continue
		}

		buffer := new(bytes.Buffer)
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

		//
		buffer.Reset()

	}
	f.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	f.done <- true
}
