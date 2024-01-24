package processors

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
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
	consumer := NewDNSTapProcessor(0, pkgconfig.GetFakeConfig(), logger, "test", 512)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion(ExpectedQname+".", dns.TypeA)
	dnsquestion, _ := dnsmsg.Pack()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion

	data, _ := proto.Marshal(dt)

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.Qname != ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}
}

func Test_DnstapProcessor_MalformedDnsHeader(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, pkgconfig.GetFakeConfig(), logger, "test", 512)
	// chanTo := make(chan dnsutils.DNSMessage, 512)

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

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_MalformedDnsQuestion(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, pkgconfig.GetFakeConfig(), logger, "test", 512)
	// chanTo := make(chan dnsutils.DNSMessage, 512)

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

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_MalformedDnsAnswer(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, pkgconfig.GetFakeConfig(), logger, "test", 512)
	// chanTo := make(chan dnsutils.DNSMessage, 512)

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

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_DisableDNSParser(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	cfg := pkgconfig.GetFakeConfig()
	cfg.Collectors.Dnstap.DisableDNSParser = true

	consumer := NewDNSTapProcessor(0, cfg, logger, "test", 512)

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

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.ID != 0 {
		t.Errorf("DNS ID should be equal to zero: %d", dm.DNS.ID)
	}
}

// test to decode the extended part
func Test_DnstapProcessor_Extended(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	cfg := pkgconfig.GetFakeConfig()
	cfg.Collectors.Dnstap.ExtendedSupport = true

	consumer := NewDNSTapProcessor(0, cfg, logger, "test", 512)

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

	edt := &dnsutils.ExtendedDnstap{}
	edt.Atags = &dnsutils.ExtendedATags{
		Tags: []string{"atags:value"},
	}
	edt.OriginalDnstapExtra = []byte("originalextrafield")
	edt.Normalize = &dnsutils.ExtendedNormalize{
		Tld:         "org",
		EtldPlusOne: "dnscollector.org",
	}
	edt.Filtering = &dnsutils.ExtendedFiltering{
		SampleRate: 30,
	}
	edtData, _ := proto.Marshal(edt)
	dt.Extra = edtData

	data, _ := proto.Marshal(dt)

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNSTap.Extra != "originalextrafield" {
		t.Errorf("invalid extra field: %s", dm.DNSTap.Extra)
	}
	if dm.ATags.Tags[0] != "atags:value" {
		t.Errorf("invalid atags: %s", dm.ATags.Tags[0])
	}
	if dm.PublicSuffix.QnameEffectiveTLDPlusOne != "dnscollector.org" {
		t.Errorf("invalid etld+1: %s", dm.PublicSuffix.QnameEffectiveTLDPlusOne)
	}
	if dm.PublicSuffix.QnamePublicSuffix != "org" {
		t.Errorf("invalid tld: %s", dm.PublicSuffix.QnamePublicSuffix)
	}
	if dm.Filtering.SampleRate != 30 {
		t.Errorf("invalid sample rate: %d", dm.Filtering.SampleRate)
	}
}

// test for issue https://github.com/dmachard/go-dnscollector/issues/568
func Test_DnstapProcessor_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 10)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, pkgconfig.GetFakeConfig(), lg, "test", 512)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion(ExpectedQname+".", dns.TypeA)
	dnsquestion, _ := dnsmsg.Pack()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion

	data, _ := proto.Marshal(dt)

	// run the consumer with a fake logger
	fl := loggers.NewFakeLoggerWithBufferSize(1)
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packets to consumer
	for i := 0; i < 512; i++ {
		consumer.GetChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.Qname != ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		consumer.GetChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	dm2 := <-fl.GetInputChannel()
	if dm2.DNS.Qname != ExpectedQname {
		t.Errorf("invalid qname in second dns message: %s", dm2.DNS.Qname)
	}
}
