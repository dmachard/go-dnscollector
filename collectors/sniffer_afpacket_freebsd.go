//go:build freebsd
// +build freebsd

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type AfpacketSniffer struct {
	done          chan bool
	exit          chan bool
	defaultRoutes []pkgutils.Worker
	config        *pkgconfig.Config
	logger        *logger.Logger
	name          string
}

// workaround for freebsd, not yet supported
func NewAfpacketSniffer(loggers []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	logger.Info("[%s] AFPACKET sniffer - enabled", name)
	s := &AfpacketSniffer{
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

func (c *AfpacketSniffer) GetName() string { return c.name }

func (c *AfpacketSniffer) AddDroppedRoute(wrk pkgutils.Worker) {
	// TODO
}

func (c *AfpacketSniffer) AddDefaultRoute(wrk pkgutils.Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *AfpacketSniffer) SetLoggers(loggers []pkgutils.Worker) {
	c.defaultRoutes = loggers
}

func (c *AfpacketSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] AFPACKET sniffer - "+msg, v...)
}

func (c *AfpacketSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] AFPACKET sniffer - "+msg, v...)
}

func (c *AfpacketSniffer) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetActiveRoutes(c.defaultRoutes)
}

func (c *AfpacketSniffer) ReadConfig() {}

func (c *AfpacketSniffer) ReloadConfig(config *pkgconfig.Config) {}

func (c *AfpacketSniffer) GetInputChannel() chan dnsutils.DNSMessage {
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
