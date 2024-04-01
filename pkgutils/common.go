package pkgutils

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type Collector struct {
	config                       *pkgconfig.Config
	configChan                   chan *pkgconfig.Config
	logger                       *logger.Logger
	name                         string
	droppedRoutes, defaultRoutes []Worker
}

func NewCollector(config *pkgconfig.Config, logger *logger.Logger, name string) *Collector {
	logger.Info(PrefixLogCollector+"[%s] collector - enabled", name)
	return &Collector{
		config:     config,
		configChan: make(chan *pkgconfig.Config),
		logger:     logger,
		name:       name,
	}
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

func (c *Collector) AddDroppedRoute(wrk Worker) {
	c.droppedRoutes = append(c.droppedRoutes, wrk)
}

func (c *Collector) AddDefaultRoute(wrk Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
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
	c.logger.Info(PrefixLogCollector+"["+c.name+"] collector - "+msg, v...)
}

func (c *Collector) LogError(msg string, v ...interface{}) {
	c.logger.Error(PrefixLogCollector+"["+c.name+"] collector - "+msg, v...)
}

func (c *Collector) LogFatal(v ...interface{}) {
	c.logger.Fatal(v...)
}
