package dnsutils

import "testing"

func TestDnsStatisticsRecord(t *testing.T) {
	stats := NewStatistics(10)

	dm := DnsMessage{}
	dm.Init()
	dm.Type = "query"
	dm.Family = "INET"
	dm.Protocol = "UDP"
	dm.Qname = "dnscollector.test."

	stats.Record(dm)

	nb := stats.GetTotalDomains()
	if nb != 1 {
		t.Errorf("invalid number of domains, expected 1, got %d", nb)
	}
}
