package processors

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func Test_DnsProcessor(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init and run the dns processor
	consumer := NewDNSProcessor(dnsutils.GetFakeConfig(), logger, "test", 512)
	chanTo := make(chan dnsutils.DNSMessage, 512)
	go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})

	dm := dnsutils.GetFakeDNSMessageWithPayload()
	consumer.GetChannel() <- dm

	// read dns message from dnstap consumer
	dmOut := <-chanTo

	if dmOut.DNS.Qname != "dnscollector.dev" {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}

}
