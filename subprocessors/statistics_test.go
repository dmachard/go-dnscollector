package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestStreamsStatisticsRecord(t *testing.T) {
	config := dnsutils.GetFakeConfig()
	stats := NewStreamsStats(config, "1.2.3")

	dm := dnsutils.DnsMessage{}
	dm.Init()
	dm.DnsPayload.Type = dnsutils.DnsQuery
	dm.NetworkInfo.Family = "INET"
	dm.NetworkInfo.Protocol = "UDP"
	dm.DnsPayload.Qname = "dnscollector.test."

	stats.Record(dm)

	nb := stats.GetTotalDomains("global")
	if nb != 1 {
		t.Errorf("invalid number of domains, expected 1, got %d", nb)
	}
}
