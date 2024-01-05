package processors

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

func Test_DnsProcessor(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init and run the dns processor
	consumer := NewDNSProcessor(pkgconfig.GetFakeConfig(), logger, "test", 512)

	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	dm := dnsutils.GetFakeDNSMessageWithPayload()
	consumer.GetChannel() <- dm

	// read dns message from dnstap consumer
	dmOut := <-fl.GetInputChannel()
	if dmOut.DNS.Qname != "dnscollector.dev" {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}

}
