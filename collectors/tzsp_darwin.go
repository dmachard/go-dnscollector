//go:build darwin
// +build darwin

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type TzspSniffer struct {
	done    chan bool
	exit    chan bool
	loggers []dnsutils.Worker
	config  *dnsutils.Config
	logger  *logger.Logger
	name    string
}

// workaround for macos, not yet supported
func NewTzsp(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	logger.Info("[%s] tzsp collector - enabled", name)
	s := &AfpacketSniffer{
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

func (c *TzspSniffer) GetName() string { return c.name }

func (c *TzspSniffer) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *TzspSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] tzsp collector - "+msg, v...)
}

func (c *TzspSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] tzsp collector - "+msg, v...)
}

func (c *TzspSniffer) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *TzspSniffer) ReadConfig() {
}

func (c *TzspSniffer) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *TzspSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *TzspSniffer) Run() {
	c.LogInfo("run terminated")
	c.done <- true
}
