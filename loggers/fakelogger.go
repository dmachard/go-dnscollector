package loggers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
)

type FakeLogger struct {
	inputChan  chan dnsutils.DNSMessage
	outputChan chan dnsutils.DNSMessage
	name       string
}

func NewFakeLogger() *FakeLogger {
	o := &FakeLogger{
		inputChan:  make(chan dnsutils.DNSMessage, 512),
		outputChan: make(chan dnsutils.DNSMessage, 512),
		name:       "fake",
	}
	return o
}

func (c *FakeLogger) GetName() string { return c.name }

func (c *FakeLogger) AddDefaultRoute(wrk pkgutils.Worker) {}

func (c *FakeLogger) AddDroppedRoute(wrk pkgutils.Worker) {}

func (c *FakeLogger) SetLoggers(loggers []pkgutils.Worker) {}

func (c *FakeLogger) ReadConfig() {}

func (c *FakeLogger) ReloadConfig(config *pkgconfig.Config) {}

func (c *FakeLogger) Stop() {}

func (c *FakeLogger) GetInputChannel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *FakeLogger) Run() {}
