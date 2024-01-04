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
	stopProcess   chan bool
	doneProcess   chan bool
	stopRun       chan bool
	doneRun       chan bool
	inputChan     chan dnsutils.DNSMessage
	outputChan    chan dnsutils.DNSMessage
	config        *pkgconfig.Config
	configChan    chan *pkgconfig.Config
	logger        *logger.Logger
	name          string
	server        string
	index         string
	bulkURL       string
	droppedCount  map[string]int
	dropped       chan string
	droppedRoutes []pkgutils.Worker
	defaultRoutes []pkgutils.Worker
}

func NewElasticSearchClient(config *pkgconfig.Config, console *logger.Logger, name string) *ElasticSearchClient {
	console.Info("[%s] logger=elasticsearch - enabled", name)
	c := &ElasticSearchClient{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DNSMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DNSMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		logger:      console,
		config:      config,
		configChan:  make(chan *pkgconfig.Config),
		name:        name,
	}
	c.ReadConfig()
	return c
}

func (c *ElasticSearchClient) GetName() string { return c.name }

func (c *ElasticSearchClient) AddDroppedRoute(wrk pkgutils.Worker) {
	c.droppedRoutes = append(c.droppedRoutes, wrk)
}

func (c *ElasticSearchClient) AddDefaultRoute(wrk pkgutils.Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *ElasticSearchClient) GetDefaultRoutes() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetActiveRoutes(c.defaultRoutes)
}

func (c *ElasticSearchClient) GetDroppedRoutes() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetActiveRoutes(c.droppedRoutes)
}

func (c *ElasticSearchClient) SetLoggers(loggers []pkgutils.Worker) {}

func (c *ElasticSearchClient) ReadConfig() {
	c.server = c.config.Loggers.ElasticSearchClient.Server
	c.index = c.config.Loggers.ElasticSearchClient.Index

	u, err := url.Parse(c.server)
	if err != nil {
		c.LogError(err.Error())
	}
	u.Path = path.Join(u.Path, c.index, "_bulk")
	c.bulkURL = u.String()
}

func (c *ElasticSearchClient) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *ElasticSearchClient) GetInputChannel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *ElasticSearchClient) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=elasticsearch - "+msg, v...)
}

func (c *ElasticSearchClient) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=elasticsearch - "+msg, v...)
}

func (c *ElasticSearchClient) Stop() {
	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess
}

func (c *ElasticSearchClient) Run() {
	c.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := c.GetDefaultRoutes()
	droppedRoutes, droppedNames := c.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, c.outputChan)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go c.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-c.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			c.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-c.configChan:
			if !opened {
				return
			}
			c.config = cfg
			c.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-c.inputChan:
			if !opened {
				c.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				for i := range droppedRoutes {
					select {
					case droppedRoutes[i] <- dm: // Successful send to logger channel
					default:
						c.dropped <- droppedNames[i]
					}
				}
				continue
			}

			// send to next ?
			for i := range defaultRoutes {
				select {
				case defaultRoutes[i] <- dm: // Successful send to logger channel
				default:
					c.dropped <- defaultNames[i]
				}
			}

			// send to output channel
			c.outputChan <- dm
		}
	}
	c.LogInfo("run terminated")
}

func (c *ElasticSearchClient) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	buffer := new(bytes.Buffer)

	for _, dm := range *buf {
		buffer.WriteString("{ \"create\" : {}}")
		buffer.WriteString("\n")
		// encode
		flat, err := dm.Flatten()
		if err != nil {
			c.LogError("flattening DNS message failed: %e", err)
		}
		json.NewEncoder(buffer).Encode(flat)
	}

	req, _ := http.NewRequest("POST", c.bulkURL, buffer)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	_, err := client.Do(req)
	if err != nil {
		c.LogError(err.Error())
	}

	*buf = nil
}

func (c *ElasticSearchClient) Process() {
	bufferDm := []dnsutils.DNSMessage{}
	c.LogInfo("ready to process")

	flushInterval := time.Duration(c.config.Loggers.ElasticSearchClient.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	nextStanzaBufferInterval := 10 * time.Second
	nextStanzaBufferFull := time.NewTimer(nextStanzaBufferInterval)

PROCESS_LOOP:
	for {
		select {
		case <-c.stopProcess:
			c.doneProcess <- true
			break PROCESS_LOOP

		case stanzaName := <-c.dropped:
			if _, ok := c.droppedCount[stanzaName]; !ok {
				c.droppedCount[stanzaName] = 1
			} else {
				c.droppedCount[stanzaName]++
			}

		// incoming dns message to process
		case dm, opened := <-c.outputChan:
			if !opened {
				c.LogInfo("output channel closed!")
				return
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= c.config.Loggers.ElasticSearchClient.BulkSize {
				c.FlushBuffer(&bufferDm)
			}
			// flush the buffer
		case <-flushTimer.C:
			if len(bufferDm) > 0 {
				c.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)

		case <-nextStanzaBufferFull.C:
			for v, k := range c.droppedCount {
				if k > 0 {
					c.LogError("stanza[%s] buffer is full, %d packet(s) dropped", v, k)
					c.droppedCount[v] = 0
				}
			}
			nextStanzaBufferFull.Reset(nextStanzaBufferInterval)
		}
	}
	c.LogInfo("processing terminated")
}
