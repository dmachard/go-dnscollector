package dnsutils

import (
	"testing"

	"github.com/dmachard/go-netutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestToPacketLayer_DoT_Translation(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm.NetworkInfo.Family = netutils.ProtoIPv4
	dm.NetworkInfo.Protocol = ProtoDoT
	dm.NetworkInfo.QueryIP = "127.0.0.8"
	dm.NetworkInfo.QueryPort = "12345"
	dm.NetworkInfo.ResponseIP = "127.0.0.10"
	dm.NetworkInfo.ResponsePort = "853"
	dm.DNS.Type = DNSQuery

	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)

	overwriteDstPort := false
	pkt, err := dm.ToPacketLayer(overwriteDstPort)
	assert.NoError(t, err)

	// check source and dest
	udpLayer, ok := pkt[1].(*layers.UDP)
	assert.True(t, ok, "Expected TCP layer")
	assert.Equal(t, 853, int(udpLayer.DstPort), "Expected destination port 853 for DoT")
	assert.NotZero(t, udpLayer.SrcPort, "Expected non-zero source port")
}

func TestToPacketLayer_DoT_OverwriteDestinationPort(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm.NetworkInfo.Family = netutils.ProtoIPv4
	dm.NetworkInfo.Protocol = ProtoDoT
	dm.NetworkInfo.QueryIP = "127.0.0.8"
	dm.NetworkInfo.QueryPort = "12345"
	dm.NetworkInfo.ResponseIP = "127.0.0.10"
	dm.NetworkInfo.ResponsePort = "853"
	dm.DNS.Type = DNSQuery

	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)

	overwriteDstPort := true
	pkt, err := dm.ToPacketLayer(overwriteDstPort)
	assert.NoError(t, err)

	// check source and dest
	udpLayer, ok := pkt[1].(*layers.UDP)
	assert.True(t, ok, "Expected TCP layer")
	assert.Equal(t, 53, int(udpLayer.DstPort), "Expected destination port 53 for DoT")
	assert.NotZero(t, udpLayer.SrcPort, "Expected non-zero source port")
}

func TestToPacketLayer_FamilyAliasesAndFallback(t *testing.T) {
	testCases := []struct {
		name       string
		family     string
		qIP        string
		rIP        string
		expectIPv6 bool
	}{
		{name: "INET_alias", family: "INET", qIP: "1.2.3.4", rIP: "5.6.7.8", expectIPv6: false},
		{name: "INET6_alias", family: "INET6", qIP: "2001:db8::1", rIP: "2001:db8::2", expectIPv6: true},
		{name: "UNKNOWN_fallback_v4", family: "UNKNOWN", qIP: "10.0.0.1", rIP: "10.0.0.2", expectIPv6: false},
		{name: "UNKNOWN_fallback_v6", family: "UNKNOWN", qIP: "2001:db8::1", rIP: "2001:db8::2", expectIPv6: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dm := DNSMessage{}
			dm.Init()
			dm.InitTransforms()

			dnsmsg := new(dns.Msg)
			dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeA)
			payload, err := dnsmsg.Pack()
			assert.NoError(t, err)

			dm.NetworkInfo.Family = tc.family
			dm.NetworkInfo.Protocol = netutils.ProtoUDP
			dm.NetworkInfo.QueryIP = tc.qIP
			dm.NetworkInfo.QueryPort = "53000"
			dm.NetworkInfo.ResponseIP = tc.rIP
			dm.NetworkInfo.ResponsePort = "53"
			dm.DNS.Type = DNSQuery
			dm.DNS.Payload = payload
			dm.DNS.Length = len(payload)

			pkt, err := dm.ToPacketLayer(false)
			assert.NoError(t, err)
			assert.NotEmpty(t, pkt)

			ethLayer, ok := pkt[len(pkt)-1].(*layers.Ethernet)
			assert.True(t, ok)
			if tc.expectIPv6 {
				assert.Equal(t, layers.EthernetTypeIPv6, ethLayer.EthernetType)
			} else {
				assert.Equal(t, layers.EthernetTypeIPv4, ethLayer.EthernetType)
			}
		})
	}
}

func TestEncodeToPacketBytes_Validation(t *testing.T) {
	testCases := []struct {
		name     string
		family   string
		proto    string
		isQuery  bool
		overPort bool
		qIP      string
		rIP      string
		qPort    string
		rPort    string
	}{
		{
			name: "IPv4_UDP_Query", family: netutils.ProtoIPv4, proto: netutils.ProtoUDP,
			isQuery: true, overPort: false, qIP: "192.168.1.50", rIP: "8.8.8.8", qPort: "43210", rPort: "53",
		},
		{
			name: "IPv4_TCP_Query", family: netutils.ProtoIPv4, proto: netutils.ProtoTCP,
			isQuery: true, overPort: false, qIP: "192.168.1.50", rIP: "8.8.8.8", qPort: "43210", rPort: "53",
		},
		{
			name: "IPv6_UDP_Reply", family: netutils.ProtoIPv6, proto: netutils.ProtoUDP,
			isQuery: false, overPort: false, qIP: "2001:db8::1", rIP: "2001:4860:4860::8888", qPort: "43210", rPort: "53",
		},
		{
			name: "IPv6_TCP_Reply", family: netutils.ProtoIPv6, proto: netutils.ProtoTCP,
			isQuery: false, overPort: false, qIP: "2001:db8::1", rIP: "2001:4860:4860::8888", qPort: "43210", rPort: "53",
		},
		{
			name: "DoT_OverwritePort", family: netutils.ProtoIPv4, proto: ProtoDoT,
			isQuery: true, overPort: true, qIP: "10.0.0.1", rIP: "1.1.1.1", qPort: "50000", rPort: "853",
		},
		{
			name: "INET_UDP_Query", family: "INET", proto: netutils.ProtoUDP,
			isQuery: true, overPort: false, qIP: "192.168.1.50", rIP: "8.8.8.8", qPort: "43210", rPort: "53",
		},
		{
			name: "INET6_UDP_Reply", family: "INET6", proto: netutils.ProtoUDP,
			isQuery: false, overPort: false, qIP: "2001:db8::1", rIP: "2001:4860:4860::8888", qPort: "43210", rPort: "53",
		},
		{
			name: "UNKNOWN_IPv4_Fallback", family: "UNKNOWN", proto: netutils.ProtoUDP,
			isQuery: true, overPort: false, qIP: "10.1.2.3", rIP: "10.3.4.5", qPort: "56598", rPort: "53",
		},
		{
			name: "UNKNOWN_IPv6_Fallback", family: "UNKNOWN", proto: netutils.ProtoUDP,
			isQuery: true, overPort: false, qIP: "2001:db8::1", rIP: "2001:4860:4860::8888", qPort: "56598", rPort: "53",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dm := DNSMessage{}
			dm.Init()
			dm.InitTransforms()

			dnsmsg := new(dns.Msg)
			dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
			dnsquestion, err := dnsmsg.Pack()
			assert.NoError(t, err)

			dm.NetworkInfo.Family = tc.family
			dm.NetworkInfo.Protocol = tc.proto
			dm.NetworkInfo.QueryIP = tc.qIP
			dm.NetworkInfo.QueryPort = tc.qPort
			dm.NetworkInfo.ResponseIP = tc.rIP
			dm.NetworkInfo.ResponsePort = tc.rPort
			if tc.isQuery {
				dm.DNS.Type = DNSQuery
			} else {
				dm.DNS.Type = DNSReply
			}
			dm.DNS.Payload = dnsquestion
			dm.DNS.Length = len(dnsquestion)

			var buf [512]byte
			pktBytes, err := dm.EncodeToPacketBytes(buf[:0], tc.overPort)
			assert.NoError(t, err)
			assert.NotEmpty(t, pktBytes)

			// Parse back with gopacket to verify spec validity
			parsedPkt := gopacket.NewPacket(pktBytes, layers.LayerTypeEthernet, gopacket.Default)
			assert.NotNil(t, parsedPkt)
			assert.NotNil(t, parsedPkt.NetworkLayer())
			assert.NotNil(t, parsedPkt.TransportLayer())
		})
	}
}

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
		_, err := dm.ToPacketLayer(false)
		if err != nil {
			b.Fatalf("could not encode to pcap: %v\n", err)
		}
	}
}
