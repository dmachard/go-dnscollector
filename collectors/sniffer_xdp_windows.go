//go:build windows
// +build windows

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type XDPSniffer struct {
	done     chan bool
	exit     chan bool
	identity string
	loggers  []dnsutils.Worker
	config   *pkgconfig.Config
	logger   *logger.Logger
	name     string
}

func NewXDPSniffer(loggers []dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *XDPSniffer {
	logger.Info("[%s] XDP collector enabled", name)
	s := &XDPSniffer{
		done:    make(chan bool),
		exit:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
		name:    name,
	}
	s.ReadConfig()
	return s
}

func (c *XDPSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] XDP collector - "+msg, v...)
}

func (c *XDPSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] XDP collector - "+msg, v...)
}

func (c *XDPSniffer) GetName() string { return c.name }

func (c *XDPSniffer) AddRoute(wrk dnsutils.Worker) {
	c.loggers = append(c.loggers, wrk)
}

func (c *XDPSniffer) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *XDPSniffer) Loggers() []chan dnsutils.DNSMessage {
	channels := []chan dnsutils.DNSMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *XDPSniffer) ReadConfig() {}

func (c *XDPSniffer) ReloadConfig(config *pkgconfig.Config) {}

func (c *XDPSniffer) Channel() chan dnsutils.DNSMessage {
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
