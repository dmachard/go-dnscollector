package transformers

import (
	"sort"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestReorderingTransform_SortByTimestamp(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Reordering.Enable = true

	// initialize logger
	log := logger.New(false)

	// create output channels
	outChans := []chan dnsutils.DNSMessage{
		make(chan dnsutils.DNSMessage, 10),
	}

	// initialize transformer
	reorder := NewReorderingTransform(config, log, "test", 0, outChans)

	dm1 := dnsutils.GetFakeDNSMessage()
	dm1.DNSTap.TimestampRFC3339 = "2024-12-20T21:12:14.786109Z"

	dm2 := dnsutils.GetFakeDNSMessage()
	dm2.DNSTap.TimestampRFC3339 = "2024-12-20T21:12:14.766361Z"

	dm3 := dnsutils.GetFakeDNSMessage()
	dm3.DNSTap.TimestampRFC3339 = "2024-12-20T21:12:14.803447Z"

	reorder.ReorderLogs(&dm1)
	reorder.ReorderLogs(&dm2)
	reorder.ReorderLogs(&dm3)

	// manually trigger a buffer flush
	reorder.flushBuffer()

	// collect results from the output channel
	var results []dnsutils.DNSMessage
	done := false
	for !done {
		select {
		case msg := <-outChans[0]:
			results = append(results, msg)
		default:
			done = true
		}
	}

	// validate order
	if len(results) != 3 {
		t.Fatalf("Expected 3 messages, got %d", len(results))
	}

	timestamps := []string{
		results[0].DNSTap.TimestampRFC3339,
		results[1].DNSTap.TimestampRFC3339,
		results[2].DNSTap.TimestampRFC3339,
	}

	if !sort.StringsAreSorted(timestamps) {
		t.Errorf("Timestamps are not sorted: %v", timestamps)
	}
}
