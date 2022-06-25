package loggers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestStreamsStatisticsRecord(t *testing.T) {
	config := dnsutils.GetFakeConfig()
	stats := NewStreamsStats(config, "1.2.3", "prom_prefix", 0, 0, 0, 0, []string{})

	dm := dnsutils.DnsMessage{}
	dm.Init()
	dm.DNS.Type = dnsutils.DnsQuery
	dm.NetworkInfo.Family = "INET"
	dm.NetworkInfo.Protocol = "UDP"
	dm.DNS.Qname = "dnscollector.test."

	stats.Record(dm)

	nb := stats.GetTotalDomains("global")
	if nb != 1 {
		t.Errorf("invalid number of domains, expected 1, got %d", nb)
	}
}
