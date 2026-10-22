package workers

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestDnsMessage_MatchSourceFromStringKeyMap(t *testing.T) {
	matchListPath := filepath.Join(t.TempDir(), "ip_addr_per_line.conf")
	if err := os.WriteFile(matchListPath, []byte("192.0.2.10\n"), 0600); err != nil {
		t.Fatalf("failed to write match source file: %v", err)
	}

	cfg := config.GetDefaultConfig()
	cfg.Collectors.DNSMessage.Matching.Include = map[string]interface{}{
		"network.query-ip": map[string]interface{}{
			"match-source": "file://" + matchListPath,
			"source-kind":  "string_list",
		},
	}

	c := NewDNSMessage(nil, cfg, logger.New(false), "test")

	matchingMessage := dnsutils.GetFakeDNSMessage()
	matchingMessage.NetworkInfo.QueryIP = "192.0.2.10"
	if !c.matcherInclude.Match(&matchingMessage) {
		t.Fatal("expected query IP from match source to be included")
	}

	nonMatchingMessage := dnsutils.GetFakeDNSMessage()
	nonMatchingMessage.NetworkInfo.QueryIP = "192.0.2.11"
	if c.matcherInclude.Match(&nonMatchingMessage) {
		t.Fatal("expected query IP absent from match source to be excluded")
	}
}

func TestDnsMessage_RoutingPolicy(t *testing.T) {
	// simulate next workers
	kept := GetWorkerForTest(config.DefaultBufferSize)
	dropped := GetWorkerForTest(config.DefaultBufferSize)

	// config for the collector
	cfg := config.GetDefaultConfig()
	cfg.Collectors.DNSMessage.Enable = true
	cfg.Collectors.DNSMessage.Matching.Include = map[string]interface{}{
		"dns.qname": "dns.collector",
	}

	// init the collector
	c := NewDNSMessage(nil, cfg, logger.New(false), "test")
	c.SetDefaultRoutes([]Worker{kept})
	c.SetDefaultDropped([]Worker{dropped})

	// start to collect and send DNS messages on it
	go c.StartCollect()
	defer c.Stop()

	// this message should be kept by the collector
	dm1 := dnsutils.GetFakeDNSMessage()
	c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm1)

	// this message should dropped by the collector
	dm2 := dnsutils.GetFakeDNSMessage()
	dm2.DNS.Qname = "dropped.collector"
	c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm2)

	// the 1er message should be in th k worker
	batchKept := <-kept.GetInputChannel()
	if len(batchKept.Messages) == 0 || batchKept.Messages[0].DNS.Qname != "dns.collector" {
		t.Errorf("invalid dns message with default routing policy")
	}

	// the 2nd message should be in the d worker
	batchDropped := <-dropped.GetInputChannel()
	if len(batchDropped.Messages) == 0 || batchDropped.Messages[0].DNS.Qname != "dropped.collector" {
		t.Errorf("invalid dns message with dropped routing policy")
	}

}

func waitForLogMatch(ch <-chan logger.LogEntry, pattern *regexp.Regexp, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return false
			}
			fmt.Println(entry)
			if pattern.MatchString(entry.Message) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func TestDnsMessage_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 512)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the collector and run-it
	cfg := config.GetDefaultConfig()
	cfg.Global.Worker.InternalMonitor = 1
	c := NewDNSMessage(nil, cfg, lg, "test")

	// init next logger with a buffer of one element
	nxt := GetWorkerForTest(1)
	c.AddDefaultRoute(nxt)

	// run collector
	go c.StartCollect()

	// add a shot of dnsmessages to collector
	for i := 0; i < 512; i++ {
		dmIn := dnsutils.GetFakeDNSMessage()
		c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)

	if !waitForLogMatch(logsChan, regexp.MustCompile(config.ExpectedBufferMsg511), 3*time.Second) {
		t.Fatal("did not receive 511 dropped message log")
	}

	// read dnsmessage from next logger
	batchOut := <-nxt.GetInputChannel()
	if len(batchOut.Messages) == 0 || batchOut.Messages[0].DNS.Qname != config.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %v", batchOut.Messages)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		dmIn := dnsutils.GetFakeDNSMessage()
		c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)

	if !waitForLogMatch(logsChan, regexp.MustCompile(config.ExpectedBufferMsg1023), 3*time.Second) {
		t.Fatal("did not receive 1023 dropped message log")
	}
	// read dnsmessage from next logger
	batch2 := <-nxt.GetInputChannel()
	if len(batch2.Messages) == 0 || batch2.Messages[0].DNS.Qname != config.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %v", batch2.Messages)
	}

	// stop all
	c.Stop()
}
