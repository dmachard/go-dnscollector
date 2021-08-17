package loggers

import "github.com/dmachard/go-dnscollector/dnsutils"

type FakeGen struct {
	channel chan dnsutils.DnsMessage
}

func NewFakeGenerator() *FakeGen {
	o := &FakeGen{
		channel: make(chan dnsutils.DnsMessage, 512),
	}
	return o
}

func (o *FakeGen) Stop() {}

func (o *FakeGen) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *FakeGen) Run() {}
