package pkgutils

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

const (
	ExpectedQname = "dns.collector"
)

func Test_RoutingHandler_AddDefaultRoute(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 10)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// create routing handler
	rh := NewRoutingHandler(pkgconfig.GetFakeConfig(), lg, "test")

	// add default routes
	nxt := NewFakeLogger()
	rh.AddDefaultRoute(nxt)

	// get default routes
	defaultRoutes, defaultNames := rh.GetDefaultRoutes()

	// send dns message
	dmIn := dnsutils.GetFakeDNSMessage()
	rh.SendTo(defaultRoutes, defaultNames, dmIn)

	// read dns message from next item
	dmOut := <-nxt.GetInputChannel()
	if dmOut.DNS.Qname != ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dmOut.DNS.Qname)
	}

	// stop
	rh.Stop()
}

func Test_RoutingHandler_BufferIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 10)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// create routing handler
	rh := NewRoutingHandler(pkgconfig.GetFakeConfig(), lg, "test")

	// add default routes
	nxt := NewFakeLoggerWithBufferSize(1)
	rh.AddDefaultRoute(nxt)

	// add a shot of dnsmessages to collector
	defaultRoutes, defaultNames := rh.GetDefaultRoutes()
	dmIn := dnsutils.GetFakeDNSMessage()
	for i := 0; i < 512; i++ {
		rh.SendTo(defaultRoutes, defaultNames, dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(".*buffer is full, 511.*")
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	dmOut := <-nxt.GetInputChannel()
	if dmOut.DNS.Qname != ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dmOut.DNS.Qname)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		rh.SendTo(defaultRoutes, defaultNames, dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)
	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(".*buffer is full, 1023.*")
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	dmOut2 := <-nxt.GetInputChannel()
	if dmOut2.DNS.Qname != ExpectedQname {
		t.Errorf("invalid qname in second dns message: %s", dmOut2.DNS.Qname)
	}

	// stop
	rh.Stop()
}
