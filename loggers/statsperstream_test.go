package loggers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestDnsStatisticsRecord(t *testing.T) {
	config := dnsutils.GetFakeConfig()
	stats := NewStatsPerStream(config, "test", 0, 0, 0, 0, []string{})

	dm := dnsutils.DnsMessage{}
	dm.Init()
	dm.DNS.Type = dnsutils.DnsQuery
	dm.NetworkInfo.Family = "INET"
	dm.NetworkInfo.Protocol = "UDP"
	dm.DNS.Qname = "dnscollector.test."

	stats.Record(dm)

	nb := stats.GetTotalDomains()
	if nb != 1 {
		t.Errorf("invalid number of domains, expected 1, got %d", nb)
	}
}
