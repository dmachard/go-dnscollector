//go:build windows
// +build windows

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type XDPSniffer struct {
	done          chan bool
	exit          chan bool
	identity      string
	defaultRoutes []pkgutils.Worker
	config        *pkgconfig.Config
	logger        *logger.Logger
	name          string
}

func NewXDPSniffer(loggers []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *XDPSniffer {
	logger.Info(pkgutils.PrefixLogCollector+"[%s] xdp sniffer enabled", name)
	s := &XDPSniffer{
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

func (c *XDPSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info(pkgutils.PrefixLogCollector+"["+c.name+"] XDP sniffer - "+msg, v...)
}

func (c *XDPSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error(pkgutils.PrefixLogCollector+"["+c.name+"] XDP sniffer - "+msg, v...)
}

func (c *XDPSniffer) GetName() string { return c.name }

func (c *XDPSniffer) AddDroppedRoute(wrk pkgutils.Worker) {
	// TODO
}

func (c *XDPSniffer) AddDefaultRoute(wrk pkgutils.Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *XDPSniffer) SetLoggers(loggers []pkgutils.Worker) {
	c.defaultRoutes = loggers
}

func (c *XDPSniffer) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetRoutes(c.defaultRoutes)
}

func (c *XDPSniffer) ReadConfig() {}

func (c *XDPSniffer) ReloadConfig(config *pkgconfig.Config) {}

func (c *XDPSniffer) GetInputChannel() chan dnsutils.DNSMessage {
	return nil
}

func (c *XDPSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}
func (c *XDPSniffer) Run() {
	c.LogInfo("Not supported")
	c.done <- true
}
