package pkgutils

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type Collector struct {
	doneRun, stopRun             chan bool
	doneMonitor, stopMonitor     chan bool
	config                       *pkgconfig.Config
	configChan                   chan *pkgconfig.Config
	logger                       *logger.Logger
	name                         string
	descr                        string
	droppedRoutes, defaultRoutes []Worker
	droppedCount                 int
	droppedProcessor             chan int
}

func NewCollector(config *pkgconfig.Config, logger *logger.Logger, name string, descr string) *Collector {
	logger.Info(PrefixLogCollector+"[%s] %s - enabled", name, descr)
	c := &Collector{
		config:           config,
		configChan:       make(chan *pkgconfig.Config),
		logger:           logger,
		name:             name,
		descr:            descr,
		doneRun:          make(chan bool),
		doneMonitor:      make(chan bool),
		stopRun:          make(chan bool),
		stopMonitor:      make(chan bool),
		droppedProcessor: make(chan int),
	}
	go c.MonitorCollector()
	return c
}

func (c *Collector) GetName() string {
	return c.name
}

func (c *Collector) GetConfig() *pkgconfig.Config {
	return c.config
}

func (c *Collector) SetConfig(config *pkgconfig.Config) {
	c.config = config
}

func (c *Collector) NewConfig() chan *pkgconfig.Config {
	return c.configChan
}

func (c *Collector) GetLogger() *logger.Logger {
	return c.logger
}

func (c *Collector) GetDroppedRoutes() []Worker {
	return c.droppedRoutes
}

func (c *Collector) GetDefaultRoutes() []Worker {
	return c.defaultRoutes
}

func (c *Collector) GetInputChannel() chan dnsutils.DNSMessage {
	return nil
}

func (c *Collector) AddDroppedRoute(wrk Worker) {
	c.droppedRoutes = append(c.droppedRoutes, wrk)
}

func (c *Collector) AddDefaultRoute(wrk Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *Collector) SetDefaultRoutes(next []Worker) {
	c.defaultRoutes = next
}

func (c *Collector) SetLoggers(loggers []Worker) {
	c.defaultRoutes = loggers
}

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

func (c *Collector) MonitorCollector() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
MONITOR_LOOP:
	for {
		select {
		case <-c.droppedProcessor:
			c.droppedCount++
		case <-c.stopMonitor:
			close(c.droppedProcessor)
			bufferFull.Stop()
			c.doneMonitor <- true
			break MONITOR_LOOP
		case <-bufferFull.C:
			if c.droppedCount > 0 {
				c.LogError("processor buffer is full, %d packet(s) dropped", c.droppedCount)
				c.droppedCount = 0
			}
			bufferFull.Reset(watchInterval)
		}
	}
	c.LogInfo("monitor terminated")
}

func (c *Collector) ProcessorIsBusy() {
	c.droppedProcessor <- 1
}
