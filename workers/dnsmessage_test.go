package workers

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-logger"
)

func Test_DnsMessage_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 50)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the collector and run-it
	config := pkgconfig.GetFakeConfig()
	c := NewDNSMessage(nil, config, lg, "test")

	// init next logger with a buffer of one element
	nxt := pkgutils.NewFakeLoggerWithBufferSize(1)
	c.AddDefaultRoute(nxt)

	// run collector
	go c.StartCollect()

	// add a shot of dnsmessages to collector
	dmIn := dnsutils.GetFakeDNSMessage()
	for i := 0; i < 512; i++ {
		c.GetInputChannel() <- dmIn
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(processors.ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dnsmessage from next logger
	dmOut := <-nxt.GetInputChannel()
	if dmOut.DNS.Qname != processors.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %s", dmOut.DNS.Qname)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		c.GetInputChannel() <- dmIn
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(processors.ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}
	// read dnsmessage from next logger
	dm2 := <-nxt.GetInputChannel()
	if dm2.DNS.Qname != processors.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %s", dm2.DNS.Qname)
	}

	// stop all
	c.Stop()
	nxt.Stop()
}
