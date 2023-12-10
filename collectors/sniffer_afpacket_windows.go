//go:build windows
// +build windows

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type AfpacketSniffer struct {
	done    chan bool
	exit    chan bool
	loggers []dnsutils.Worker
	config  *pkgconfig.Config
	logger  *logger.Logger
	name    string
}

// workaround for macos, not yet supported
func NewAfpacketSniffer(loggers []dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	logger.Info("[%s] AFPACKET sniffer - enabled", name)
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

func (c *AfpacketSniffer) GetName() string { return c.name }

func (c *AfpacketSniffer) AddRoute(wrk dnsutils.Worker) {
	c.loggers = append(c.loggers, wrk)
}

func (c *AfpacketSniffer) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *AfpacketSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] AFPACKET sniffer - "+msg, v...)
}

func (c *AfpacketSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] AFPACKET sniffer - "+msg, v...)
}

func (c *AfpacketSniffer) Loggers() []chan dnsutils.DNSMessage {
	channels := []chan dnsutils.DNSMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *AfpacketSniffer) ReadConfig() {}

func (c *AfpacketSniffer) ReloadConfig(config *pkgconfig.Config) {}

func (c *AfpacketSniffer) Channel() chan dnsutils.DNSMessage {
	return nil
}

func (c *AfpacketSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *AfpacketSniffer) Run() {
	c.LogInfo("Not supported")
	c.done <- true
}
