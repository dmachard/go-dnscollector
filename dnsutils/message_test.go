package dnsutils

import (
	"strings"
	"testing"
)

func TestDnsMessage_TextFormat_ToString(t *testing.T) {

	config := GetFakeConfig()

	testcases := []struct {
		name      string
		delimiter string
		boundary  string
		format    string
		qname     string
		expected  string
	}{
		{
			name:      "default",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dnscollector.fr",
			expected:  "- - - - - - - - 0b dnscollector.fr - -",
		},
		{
			name:      "custom_delimiter",
			delimiter: ";",
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dnscollector.fr",
			expected:  "-;-;-;-;-;-;-;-;0b;dnscollector.fr;-;-",
		},
		{
			name:      "qname_quote",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dns collector.fr",
			expected:  "- - - - - - - - 0b \"dns collector.fr\" - -",
		},
		{
			name:      "default_boundary",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dns\"coll tor\".fr",
			expected:  "- - - - - - - - 0b \"dns\\\"coll tor\\\".fr\" - -",
		},
		{
			name:      "custom_boundary",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  "!",
			format:    config.Global.TextFormat,
			qname:     "dnscoll tor.fr",
			expected:  "- - - - - - - - 0b !dnscoll tor.fr! - -",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dm := DnsMessage{}
			dm.Init()

			dm.DNS.Qname = tc.qname

			line := dm.String(strings.Fields(tc.format), tc.delimiter, tc.boundary)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_DefaultDirectives(t *testing.T) {
	config := GetFakeConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DnsMessage
		expected string
	}{
		{
			format:   "timestamp-rfc3339ns timestamp",
			dm:       DnsMessage{DnsTap: DnsTap{TimestampRFC3339: "2023-04-22T09:17:02.906922231Z"}},
			expected: "2023-04-22T09:17:02.906922231Z 2023-04-22T09:17:02.906922231Z",
		},
		{
			format:   "timestamp-unixns timestamp-unixus timestamp-unixms",
			dm:       DnsMessage{DnsTap: DnsTap{Timestamp: 1682152174001850960}},
			expected: "1682152174001850960 1682152174001850 1682152174001",
		},
		{
			format:   "latency",
			dm:       DnsMessage{DnsTap: DnsTap{LatencySec: "0.00001"}},
			expected: "0.00001",
		},
		{
			format:   "qname qtype opcode",
			dm:       DnsMessage{DNS: Dns{Qname: "dnscollector.fr", Qtype: "AAAA", Opcode: 42}},
			expected: "dnscollector.fr AAAA 42",
		},
		{
			format:   "operation",
			dm:       DnsMessage{DnsTap: DnsTap{Operation: "CLIENT_QUERY"}},
			expected: "CLIENT_QUERY",
		},
		{
			format:   "family protocol",
			dm:       DnsMessage{NetworkInfo: DnsNetInfo{Family: "IPv4", Protocol: "UDP"}},
			expected: "IPv4 UDP",
		},
		{
			format:   "length",
			dm:       DnsMessage{DNS: Dns{Length: 42}},
			expected: "42b",
		},
		{
			format:   "malformed",
			dm:       DnsMessage{DNS: Dns{MalformedPacket: true}},
			expected: "PKTERR",
		},
		{
			format:   "tc aa ra ad",
			dm:       DnsMessage{DNS: Dns{Flags: DnsFlags{TC: true, AA: true, RA: true, AD: true}}},
			expected: "TC AA RA AD",
		},
		{
			format:   "repeated",
			dm:       DnsMessage{DNS: Dns{Repeated: 42}},
			expected: "42",
		},
		{
			format:   "df tr",
			dm:       DnsMessage{NetworkInfo: DnsNetInfo{IpDefragmented: true, TcpReassembled: true}},
			expected: "DF TR",
		},
		{
			format:   "queryip queryport",
			dm:       DnsMessage{NetworkInfo: DnsNetInfo{QueryIp: "1.2.3.4", QueryPort: "4200"}},
			expected: "1.2.3.4 4200",
		},
		{
			format:   "responseip responseport",
			dm:       DnsMessage{NetworkInfo: DnsNetInfo{ResponseIp: "1.2.3.4", ResponsePort: "4200"}},
			expected: "1.2.3.4 4200",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.format, func(t *testing.T) {
			line := tc.dm.String(strings.Fields(tc.format), config.Global.TextFormatDelimiter, config.Global.TextFormatBoundary)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}
