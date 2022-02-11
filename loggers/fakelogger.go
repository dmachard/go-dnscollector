package loggers

import "github.com/dmachard/go-dnscollector/dnsutils"

type FakeLogger struct {
	channel chan dnsutils.DnsMessage
}

func NewFakeLogger() *FakeLogger {
	o := &FakeLogger{
		channel: make(chan dnsutils.DnsMessage, 512),
	}
	return o
}

func (o *FakeLogger) ReadConfig() {}

func (o *FakeLogger) Stop() {}

func (o *FakeLogger) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *FakeLogger) Run() {}
