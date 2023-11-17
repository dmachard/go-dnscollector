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
	consumer := NewDnsProcessor(dnsutils.GetFakeConfig(), logger, "test", 512)
	chan_to := make(chan dnsutils.DnsMessage, 512)
	go consumer.Run([]chan dnsutils.DnsMessage{chan_to}, []string{"test"})

	dm := dnsutils.GetFakeDnsMessageWithPayload()
	consumer.GetChannel() <- dm

	// read dns message from dnstap consumer
	dmOut := <-chan_to

	if dmOut.DNS.Qname != "dnscollector.dev" {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}

}
