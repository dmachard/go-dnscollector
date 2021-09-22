package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestStreamsStatisticsRecord(t *testing.T) {
	config := dnsutils.GetFakeConfig()
	stats := NewStreamsStats(config)

	dm := dnsutils.DnsMessage{}
	dm.Init()
	dm.Type = "query"
	dm.Family = "INET"
	dm.Protocol = "UDP"
	dm.Qname = "dnscollector.test."

	stats.Record(dm)

	nb := stats.GetTotalDomains("global")
	if nb != 1 {
		t.Errorf("invalid number of domains, expected 1, got %d", nb)
	}
}
