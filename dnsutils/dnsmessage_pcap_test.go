package dnsutils

import (
	"testing"

	"github.com/dmachard/go-netutils"
	"github.com/miekg/dns"
)

// Tests for PCAP serialization
func BenchmarkDnsMessage_ToPacketLayer(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm.NetworkInfo.Family = netutils.ProtoIPv4
	dm.NetworkInfo.Protocol = netutils.ProtoUDP
	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.ToPacketLayer()
		if err != nil {
			b.Fatalf("could not encode to pcap: %v\n", err)
		}
	}
}
