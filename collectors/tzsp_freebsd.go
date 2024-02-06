//go:build freebsd
// +build freebsd

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type TZSPSniffer struct {
	done          chan bool
	exit          chan bool
	defaultRoutes []pkgutils.Worker
	config        *pkgconfig.Config
	logger        *logger.Logger
	name          string
}

// workaround for macos, not yet supported
func NewTZSP(loggers []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *TZSPSniffer {
	logger.Info(pkgutils.PrefixLogCollector+"[%s] tzsp - enabled", name)
	s := &TZSPSniffer{
		done:          make(chan bool),
		exit:          make(chan bool),
		config:        config,
		defaultRoutes: loggers,
		logger:        logger,
		name:          name,
	}
	s.ReadConfig()
	return s
}

func (c *TZSPSniffer) GetName() string { return c.name }

func (c *TZSPSniffer) AddDroppedRoute(wrk pkgutils.Worker) {
	// TODO
}

func (c *TZSPSniffer) AddDefaultRoute(wrk pkgutils.Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *TZSPSniffer) SetLoggers(loggers []pkgutils.Worker) {
	c.defaultRoutes = loggers
}

func (c *TZSPSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info(pkgutils.PrefixLogCollector+"["+c.name+"] tzsp - "+msg, v...)
}

func (c *TZSPSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error(pkgutils.PrefixLogCollector+"["+c.name+"] tzsp - "+msg, v...)
}

func (c *TZSPSniffer) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetRoutes(c.defaultRoutes)
}

func (c *TZSPSniffer) ReadConfig() {}

func (c *TZSPSniffer) ReloadConfig(config *pkgconfig.Config) {}

func (c *TZSPSniffer) GetInputChannel() chan dnsutils.DNSMessage {
	return nil
}

func (c *TZSPSniffer) Stop() {
	c.LogInfo("stopping collector...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *TZSPSniffer) Run() {
	c.LogInfo("run terminated")
	c.done <- true
}
