package workers

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestDnsMessage_RoutingPolicy(t *testing.T) {
	// simulate next workers
	k := GetWorkerForTest(pkgconfig.DefaultBufferSize)
	d := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// config for the collector
	config := pkgconfig.GetDefaultConfig()
	config.Collectors.DNSMessage.Enable = true
	config.Collectors.DNSMessage.Matching.Include = map[string]interface{}{
		"dns.qname": "dns.collector",
	}

	// init the collector
	c := NewDNSMessage(nil, config, logger.New(false), "test")
	c.SetDefaultRoutes([]Worker{k})
	c.SetDefaultDropped([]Worker{d})

	// start to collect and send DNS messages on it
	go c.StartCollect()

	// this message should be kept by the collector
	dm := dnsutils.GetFakeDNSMessage()
	c.GetInputChannel() <- dm

	// this message should dropped by the collector
	dm.DNS.Qname = "dropped.collector"
	c.GetInputChannel() <- dm

	// the 1er message should be in th k worker
	dmKept := <-k.GetInputChannel()
	if dmKept.DNS.Qname != "dns.collector" {
		t.Errorf("invalid dns message with default routing policy")
	}

	// the 2nd message should be in the d worker
	dmDropped := <-d.GetInputChannel()
	if dmDropped.DNS.Qname != "dropped.collector" {
		t.Errorf("invalid dns message with dropped routing policy")
	}

}

func TestDnsMessage_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 50)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the collector and run-it
	config := pkgconfig.GetDefaultConfig()
	c := NewDNSMessage(nil, config, lg, "test")

	// init next logger with a buffer of one element
	nxt := GetWorkerForTest(1)
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
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dnsmessage from next logger
	dmOut := <-nxt.GetInputChannel()
	if dmOut.DNS.Qname != pkgconfig.ExpectedQname2 {
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
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}
	// read dnsmessage from next logger
	dm2 := <-nxt.GetInputChannel()
	if dm2.DNS.Qname != pkgconfig.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %s", dm2.DNS.Qname)
	}

	// stop all
	c.Stop()
}
