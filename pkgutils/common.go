package pkgutils

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type Collector struct {
	doneRun, stopRun, doneMonitor, stopMonitor chan bool
	config                                     *pkgconfig.Config
	configChan                                 chan *pkgconfig.Config
	logger                                     *logger.Logger
	name, descr                                string
	droppedRoutes, defaultRoutes               []Worker
	droppedProcessorCount                      int
	droppedProcessor                           chan int
	droppedStanza                              chan string
	droppedStanzaCount                         map[string]int
}

func NewCollector(config *pkgconfig.Config, logger *logger.Logger, name string, descr string) *Collector {
	logger.Info(PrefixLogCollector+"[%s] %s - enabled", name, descr)
	c := &Collector{
		config:             config,
		configChan:         make(chan *pkgconfig.Config),
		logger:             logger,
		name:               name,
		descr:              descr,
		doneRun:            make(chan bool),
		doneMonitor:        make(chan bool),
		stopRun:            make(chan bool),
		stopMonitor:        make(chan bool),
		droppedProcessor:   make(chan int),
		droppedStanza:      make(chan string),
		droppedStanzaCount: map[string]int{},
	}
	go c.Monitor()
	return c
}

func (c *Collector) GetName() string { return c.name }

func (c *Collector) GetConfig() *pkgconfig.Config { return c.config }

func (c *Collector) SetConfig(config *pkgconfig.Config) { c.config = config }

func (c *Collector) ReadConfig() {}

func (c *Collector) NewConfig() chan *pkgconfig.Config { return c.configChan }

func (c *Collector) GetLogger() *logger.Logger { return c.logger }

func (c *Collector) GetDroppedRoutes() []Worker { return c.droppedRoutes }

func (c *Collector) GetDefaultRoutes() []Worker { return c.defaultRoutes }

func (c *Collector) GetInputChannel() chan dnsutils.DNSMessage { return nil }

func (c *Collector) AddDroppedRoute(wrk Worker) {
	c.droppedRoutes = append(c.droppedRoutes, wrk)
}

func (c *Collector) AddDefaultRoute(wrk Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *Collector) SetDefaultRoutes(next []Worker) {
	c.defaultRoutes = next
}

func (c *Collector) SetLoggers(loggers []Worker) { c.defaultRoutes = loggers }

func (c *Collector) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return GetRoutes(c.defaultRoutes)
}

func (c *Collector) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration...")
	c.configChan <- config
}

func (c *Collector) LogInfo(msg string, v ...interface{}) {
	c.logger.Info(PrefixLogCollector+"["+c.name+"] "+c.descr+" - "+msg, v...)
}

func (c *Collector) LogError(msg string, v ...interface{}) {
	c.logger.Error(PrefixLogCollector+"["+c.name+"] "+c.descr+" - "+msg, v...)
}

func (c *Collector) LogFatal(v ...interface{}) {
	c.logger.Fatal(v...)
}

func (c *Collector) OnStop() chan bool {
	return c.stopRun
}

func (c *Collector) StopIsDone() {
	c.doneRun <- true
}

func (c *Collector) Stop() {
	// stop monitor goroutine
	c.LogInfo("stopping monitor...")
	c.stopMonitor <- true
	<-c.doneMonitor

	// read done channel and block until run is terminated
	c.LogInfo("stopping run...")
	c.stopRun <- true
	<-c.doneRun
}

func (c *Collector) Monitor() {
	defer func() {
		c.LogInfo("monitor terminated")
		c.doneMonitor <- true
	}()

	c.LogInfo("start monitor")
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
	for {
		select {
		case <-c.droppedProcessor:
			c.droppedProcessorCount++

		case loggerName := <-c.droppedStanza:
			if _, ok := c.droppedStanzaCount[loggerName]; !ok {
				c.droppedStanzaCount[loggerName] = 1
			} else {
				c.droppedStanzaCount[loggerName]++
			}

		case <-c.stopMonitor:
			close(c.droppedProcessor)
			close(c.droppedStanza)
			bufferFull.Stop()
			return

		case <-bufferFull.C:
			if c.droppedProcessorCount > 0 {
				c.LogError("processor buffer is full, %d dnsmessage(s) dropped", c.droppedProcessorCount)
				c.droppedProcessorCount = 0
			}

			for v, k := range c.droppedStanzaCount {
				if k > 0 {
					c.LogError("stanza[%s] buffer is full, %d dnsmessage(s) dropped", v, k)
					c.droppedStanzaCount[v] = 0
				}
			}

			bufferFull.Reset(watchInterval)
		}
	}
}

func (c *Collector) ProcessorIsBusy() {
	c.droppedProcessor <- 1
}

func (c *Collector) NextStanzaIsBusy(name string) {
	c.droppedStanza <- name
}

func (c *Collector) Run() {
	c.LogInfo("running in background...")
	defer func() {
		c.LogInfo("run terminated")
		c.StopIsDone()
	}()
}
