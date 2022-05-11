//go:build darwin
// +build darwin

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type DnsSniffer struct {
	done    chan bool
	exit    chan bool
	loggers []dnsutils.Worker
	config  *dnsutils.Config
	logger  *logger.Logger
}

// workaround for macos, not yet supported
func NewDnsSniffer(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger) *DnsSniffer {
	logger.Info("collector dns sniffer - enabled")
	s := &DnsSniffer{
		done:    make(chan bool),
		exit:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
	}
	s.ReadConfig()
	return s
}

func (c *DnsSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("collector dns sniffer - "+msg, v...)
}

func (c *DnsSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("collector dns sniffer - "+msg, v...)
}

func (c *DnsSniffer) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *DnsSniffer) ReadConfig() {
}

func (c *DnsSniffer) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *DnsSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *DnsSniffer) Run() {
	c.LogInfo("run terminated")
	c.done <- true
}
