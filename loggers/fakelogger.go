package loggers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
)

type FakeLogger struct {
	inputChan  chan dnsutils.DnsMessage
	outputChan chan dnsutils.DnsMessage
	name       string
}

func NewFakeLogger() *FakeLogger {
	o := &FakeLogger{
		inputChan:  make(chan dnsutils.DnsMessage, 512),
		outputChan: make(chan dnsutils.DnsMessage, 512),
		name:       "fake",
	}
	return o
}

func (c *FakeLogger) GetName() string { return c.name }

func (c *FakeLogger) SetLoggers(loggers []dnsutils.Worker) {}

func (o *FakeLogger) ReadConfig() {}

func (o *FakeLogger) Stop() {}

func (o *FakeLogger) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *FakeLogger) Run() {}
