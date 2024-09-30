package workers

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

func Test_DnsProcessor(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init and run the dns processor
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	consumer := NewDNSProcessor(pkgconfig.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)
	go consumer.StartCollect()

	dm := dnsutils.GetFakeDNSMessageWithPayload()
	consumer.GetInputChannel() <- dm

	// read dns message from dnstap consumer
	dmOut := <-fl.GetInputChannel()
	if dmOut.DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}
}

func Test_DnsProcessor_DecodeCounters(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init and run the dns processor
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	consumer := NewDNSProcessor(pkgconfig.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)
	go consumer.StartCollect()

	// get dns packet
	responsePacket, _ := dnsutils.GetDnsResponsePacket()

	// prepare dns message
	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.Family = netutils.ProtoIPv4
	dm.NetworkInfo.Protocol = netutils.ProtoUDP
	dm.DNS.Payload = responsePacket
	dm.DNS.Length = len(responsePacket)

	// send dm to consumer
	consumer.GetInputChannel() <- dm

	// read dns message from dnstap consumer
	dmOut := <-fl.GetInputChannel()
	if dmOut.DNS.QdCount != 1 {
		t.Errorf("invalid number of questions in dns message: %d", dmOut.DNS.QdCount)
	}
	if dmOut.DNS.NsCount != 1 {
		t.Errorf("invalid number of nscount in dns message: %d", dmOut.DNS.NsCount)
	}
	if dmOut.DNS.AnCount != 1 {
		t.Errorf("invalid number of ancount in dns message: %d", dmOut.DNS.AnCount)
	}
	if dmOut.DNS.ArCount != 1 {
		t.Errorf("invalid number of arcount in dns message: %d", dmOut.DNS.ArCount)
	}
}

func Test_DnsProcessor_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 10)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init and run the dns processor
	fl := GetWorkerForTest(pkgconfig.DefaultBufferOne)
	consumer := NewDNSProcessor(pkgconfig.GetDefaultConfig(), lg, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)
	go consumer.StartCollect()

	dm := dnsutils.GetFakeDNSMessageWithPayload()

	// add packets to consumer
	for i := 0; i < 512; i++ {
		consumer.GetInputChannel() <- dm
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	dmOut := <-fl.GetInputChannel()
	if dmOut.DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dmOut.DNS.Qname)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		consumer.GetInputChannel() <- dm
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	dm2 := <-fl.GetInputChannel()
	if dm2.DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in second dns message: %s", dm2.DNS.Qname)
	}
}
