package collectors

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-logger"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func Test_DnstapProcessor(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewDnstapProcessor(dnsutils.GetFakeConfig(), logger, "test")
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
	if dm.DNS.Qname != "www.google.fr" {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}
}

func Test_DnstapProcessor_MalformedDnsHeader(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewDnstapProcessor(dnsutils.GetFakeConfig(), logger, "test")
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
	dt.Message.QueryMessage = dnsquestion[:4]

	data, _ := proto.Marshal(dt)

	go consumer.Run([]chan dnsutils.DnsMessage{chan_to})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-chan_to
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_MalformedDnsQuestion(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewDnstapProcessor(dnsutils.GetFakeConfig(), logger, "test")
	chan_to := make(chan dnsutils.DnsMessage, 512)

	// prepare dns query
	dnsquestion := []byte{88, 27, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112,
		99, 111, 108, 108, 101, 99, 116, 111, 114, 4, 116, 101, 115, 116, 0}

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
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_MalformedDnsAnswer(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewDnstapProcessor(dnsutils.GetFakeConfig(), logger, "test")
	chan_to := make(chan dnsutils.DnsMessage, 512)

	// prepare dns query
	dnsanswer := []byte{46, 172, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 127, 0}

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(6)
	dt.Message.ResponseMessage = dnsanswer

	data, _ := proto.Marshal(dt)

	go consumer.Run([]chan dnsutils.DnsMessage{chan_to})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-chan_to
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}
