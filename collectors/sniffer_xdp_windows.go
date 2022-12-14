//go:build windows
// +build windows

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type XdpSniffer struct {
	done     chan bool
	exit     chan bool
	identity string
	loggers  []dnsutils.Worker
	config   *dnsutils.Config
	logger   *logger.Logger
	name     string
}

func NewXdpSniffer(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *XdpSniffer {
	logger.Info("[%s] XDP collector enabled", name)
	s := &XdpSniffer{
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

func (c *XdpSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] XDP collector - "+msg, v...)
}

func (c *XdpSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] XDP collector - "+msg, v...)
}

func (c *XdpSniffer) GetName() string { return c.name }

func (c *XdpSniffer) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *XdpSniffer) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *XdpSniffer) ReadConfig() {
	c.identity = c.config.GetServerIdentity()
}

func (c *XdpSniffer) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *XdpSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}
func (c *XdpSniffer) Run() {
	c.LogInfo("Not supported")
	c.done <- true
}
