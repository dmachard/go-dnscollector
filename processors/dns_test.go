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
	if dmOut.DNS.Qname != ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}
}

func Test_DnsProcessor_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 10)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init and run the dns processor
	consumer := NewDNSProcessor(pkgconfig.GetFakeConfig(), lg, "test", 512)

	fl := loggers.NewFakeLoggerWithBufferSize(1)
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	dm := dnsutils.GetFakeDNSMessageWithPayload()

	// add packets to consumer
	for i := 0; i < 512; i++ {
		consumer.GetChannel() <- dm
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
	dmOut := <-fl.GetInputChannel()
	if dmOut.DNS.Qname != ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dmOut.DNS.Qname)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		consumer.GetChannel() <- dm
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
