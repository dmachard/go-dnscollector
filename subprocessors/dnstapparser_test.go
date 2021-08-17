package subprocessors

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-logger"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func TestDnstapProcessor(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewDnstapProcessor(dnsutils.GetFakeConfig(), logger)
	chan_to := make(chan dnsutils.DnsMessage, 512)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("www.google.fr.", dns.TypeA)
	dnsquestion, _ := dnsmsg.Pack()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion

	data, _ := proto.Marshal(dt)

	go consumer.Run([]chan dnsutils.DnsMessage{chan_to})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-chan_to
	if dm.Qname != "www.google.fr" {
		t.Errorf("invalid qname in dns message: %s", dm.Qname)
	}

}
