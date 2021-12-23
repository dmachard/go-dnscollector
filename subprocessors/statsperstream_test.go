package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestDnsStatisticsRecord(t *testing.T) {
	config := dnsutils.GetFakeConfig()
	stats := NewStatsPerStream(config)

	dm := dnsutils.DnsMessage{}
	dm.Init()
	dm.Type = "query"
	dm.NetworkInfo.Family = "INET"
	dm.NetworkInfo.Protocol = "UDP"
	dm.Qname = "dnscollector.test."

	stats.Record(dm)

	nb := stats.GetTotalDomains()
	if nb != 1 {
		t.Errorf("invalid number of domains, expected 1, got %d", nb)
	}
}
