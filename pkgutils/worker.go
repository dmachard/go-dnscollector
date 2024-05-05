package pkgutils

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type Worker interface {
	AddDefaultRoute(wrk Worker)
	AddDroppedRoute(wrk Worker)
	SetLoggers(loggers []Worker)
	GetName() string
	Stop()
	Run()
	GetInputChannel() chan dnsutils.DNSMessage
	ReadConfig()
	ReloadConfig(config *pkgconfig.Config)
}

type GenericWorker struct {
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
	dnsMessageIn, dnsMessageOut                chan dnsutils.DNSMessage
}

func NewGenericWorker(config *pkgconfig.Config, logger *logger.Logger, name string, descr string, bufferSize int) *GenericWorker {
	logger.Info(PrefixLogCollector+"[%s] %s - enabled", name, descr)
	c := &GenericWorker{
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
		dnsMessageIn:       make(chan dnsutils.DNSMessage, bufferSize),
		dnsMessageOut:      make(chan dnsutils.DNSMessage, bufferSize),
	}
	go c.Monitor()
	return c
}

func (c *GenericWorker) GetName() string { return c.name }

func (c *GenericWorker) GetConfig() *pkgconfig.Config { return c.config }

func (c *GenericWorker) SetConfig(config *pkgconfig.Config) { c.config = config }

func (c *GenericWorker) ReadConfig() {}

func (c *GenericWorker) NewConfig() chan *pkgconfig.Config { return c.configChan }

func (c *GenericWorker) GetLogger() *logger.Logger { return c.logger }

func (c *GenericWorker) GetDroppedRoutes() []Worker { return c.droppedRoutes }

func (c *GenericWorker) GetDefaultRoutes() []Worker { return c.defaultRoutes }

func (c *GenericWorker) GetInputChannel() chan dnsutils.DNSMessage { return c.dnsMessageIn }

func (c *GenericWorker) GetOutputChannel() chan dnsutils.DNSMessage { return c.dnsMessageOut }

func (c *GenericWorker) AddDroppedRoute(wrk Worker) {
	c.droppedRoutes = append(c.droppedRoutes, wrk)
}

func (c *GenericWorker) AddDefaultRoute(wrk Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *GenericWorker) SetDefaultRoutes(next []Worker) {
	c.defaultRoutes = next
}

func (c *GenericWorker) SetLoggers(loggers []Worker) { c.defaultRoutes = loggers }

func (c *GenericWorker) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return GetRoutes(c.defaultRoutes)
}

func (c *GenericWorker) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration...")
	c.configChan <- config
}

func (c *GenericWorker) LogInfo(msg string, v ...interface{}) {
	c.logger.Info(PrefixLogCollector+"["+c.name+"] "+c.descr+" - "+msg, v...)
}

func (c *GenericWorker) LogError(msg string, v ...interface{}) {
	c.logger.Error(PrefixLogCollector+"["+c.name+"] "+c.descr+" - "+msg, v...)
}

func (c *GenericWorker) LogFatal(v ...interface{}) {
	c.logger.Fatal(v...)
}

func (c *GenericWorker) OnStop() chan bool {
	return c.stopRun
}

func (c *GenericWorker) StopIsDone() {
	c.doneRun <- true
}

func (c *GenericWorker) Stop() {
	// stop monitor goroutine
	c.LogInfo("stopping monitor...")
	c.stopMonitor <- true
	<-c.doneMonitor

	// read done channel and block until run is terminated
	c.LogInfo("stopping run...")
	c.stopRun <- true
	<-c.doneRun
}

func (c *GenericWorker) Monitor() {
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
					c.LogError("worker[%s] buffer is full, %d dnsmessage(s) dropped", v, k)
					c.droppedStanzaCount[v] = 0
				}
			}

			bufferFull.Reset(watchInterval)
		}
	}
}

func (c *GenericWorker) ProcessorIsBusy() {
	c.droppedProcessor <- 1
}

func (c *GenericWorker) NextStanzaIsBusy(name string) {
	c.droppedStanza <- name
}

func (c *GenericWorker) Run() {
	c.LogInfo("running in background...")
	defer func() {
		c.LogInfo("run terminated")
		c.StopIsDone()
	}()
}
