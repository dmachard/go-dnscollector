package dnsutils

import (
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/pkgconfig"
)

// Tests for TEXT format
func TestDnsMessage_TextFormat_ToString(t *testing.T) {

	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name      string
		delimiter string
		boundary  string
		format    string
		qname     string
		identity  string
		expected  string
	}{
		{
			name:      "default",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dnscollector.fr",
			identity:  "collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 - - 0b dnscollector.fr A 0.000000000",
		},
		{
			name:      "custom_delimiter",
			delimiter: ";",
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dnscollector.fr",
			identity:  "collector",
			expected:  "-;collector;CLIENT_QUERY;NOERROR;1.2.3.4;1234;-;-;0b;dnscollector.fr;A;0.000000000",
		},
		{
			name:      "empty_delimiter",
			delimiter: "",
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dnscollector.fr",
			identity:  "collector",
			expected:  "-collectorCLIENT_QUERYNOERROR1.2.3.41234--0bdnscollector.frA0.000000000",
		},
		{
			name:      "qname_quote",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dns collector.fr",
			identity:  "collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 - - 0b \"dns collector.fr\" A 0.000000000",
		},
		{
			name:      "default_boundary",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    config.Global.TextFormat,
			qname:     "dns\"coll tor\".fr",
			identity:  "collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 - - 0b \"dns\\\"coll tor\\\".fr\" A 0.000000000",
		},
		{
			name:      "custom_boundary",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  "!",
			format:    config.Global.TextFormat,
			qname:     "dnscoll tor.fr",
			identity:  "collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 - - 0b !dnscoll tor.fr! A 0.000000000",
		},
		{
			name:      "custom_text",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    "qname {IN} qtype",
			qname:     "dnscollector.fr",
			identity:  "",
			expected:  "dnscollector.fr IN A",
		},
		{
			name:      "quote_dnstap_version",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    "identity version qname",
			qname:     "dnscollector.fr",
			identity:  "collector",
			expected:  "collector \"dnscollector 1.0.0\" dnscollector.fr",
		},
		{
			name:      "quote_dnstap_identity",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    "identity qname",
			qname:     "dnscollector.fr",
			identity:  "dns collector",
			expected:  "\"dns collector\" dnscollector.fr",
		},
		{
			name:      "quote_dnstap_peername",
			delimiter: config.Global.TextFormatDelimiter,
			boundary:  config.Global.TextFormatBoundary,
			format:    "peer-name qname",
			qname:     "dnscollector.fr",
			identity:  "",
			expected:  "\"localhost (127.0.0.1)\" dnscollector.fr",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dm := GetFakeDNSMessage()

			dm.DNS.Qname = tc.qname
			dm.DNSTap.Identity = tc.identity

			line := dm.String(strings.Fields(tc.format), tc.delimiter, tc.boundary)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_DefaultDirectives(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			format:   "timestamp-rfc3339ns timestamp",
			dm:       DNSMessage{DNSTap: DNSTap{TimestampRFC3339: "2023-04-22T09:17:02.906922231Z"}},
			expected: "2023-04-22T09:17:02.906922231Z 2023-04-22T09:17:02.906922231Z",
		},
		{
			format:   "timestamp-unixns timestamp-unixus timestamp-unixms",
			dm:       DNSMessage{DNSTap: DNSTap{Timestamp: 1682152174001850960}},
			expected: "1682152174001850960 1682152174001850 1682152174001",
		},
		{
			format:   "latency",
			dm:       DNSMessage{DNSTap: DNSTap{Latency: 0.00001}},
			expected: "0.000010000",
		},
		{
			format:   "qname qtype opcode",
			dm:       DNSMessage{DNS: DNS{Qname: "dnscollector.fr", Qtype: "AAAA", Opcode: 42}},
			expected: "dnscollector.fr AAAA 42",
		},
		{
			format:   "qclass",
			dm:       DNSMessage{DNS: DNS{Qclass: "CH"}},
			expected: "CH",
		},
		{
			format:   "operation",
			dm:       DNSMessage{DNSTap: DNSTap{Operation: "CLIENT_QUERY"}},
			expected: "CLIENT_QUERY",
		},
		{
			format:   "family protocol",
			dm:       DNSMessage{NetworkInfo: DNSNetInfo{Family: "IPv4", Protocol: "UDP"}},
			expected: "IPv4 UDP",
		},
		{
			format:   "length",
			dm:       DNSMessage{DNS: DNS{Length: 42}},
			expected: "42",
		},
		{
			format:   "length-unit",
			dm:       DNSMessage{DNS: DNS{Length: 42}},
			expected: "42b",
		},
		{
			format:   "malformed",
			dm:       DNSMessage{DNS: DNS{MalformedPacket: true}},
			expected: "PKTERR",
		},
		{
			format:   "tc aa ra ad",
			dm:       DNSMessage{DNS: DNS{Flags: DNSFlags{TC: true, AA: true, RA: true, AD: true}}},
			expected: "TC AA RA AD",
		},
		{
			format:   "rd",
			dm:       DNSMessage{DNS: DNS{Flags: DNSFlags{RD: true}}},
			expected: "RD",
		},
		{
			format:   "tc aa ra ad rd",
			dm:       DNSMessage{DNS: DNS{Flags: DNSFlags{TC: false, AA: false, RA: false, AD: false, RD: false}}},
			expected: "- - - - -",
		},
		{
			format:   "df tr",
			dm:       DNSMessage{NetworkInfo: DNSNetInfo{IPDefragmented: true, TCPReassembled: true}},
			expected: "DF TR",
		},
		{
			format:   "queryip queryport",
			dm:       DNSMessage{NetworkInfo: DNSNetInfo{QueryIP: "1.2.3.4", QueryPort: "4200"}},
			expected: "1.2.3.4 4200",
		},
		{
			format:   "responseip responseport",
			dm:       DNSMessage{NetworkInfo: DNSNetInfo{ResponseIP: "1.2.3.4", ResponsePort: "4200"}},
			expected: "1.2.3.4 4200",
		},
		{
			format: "policy-rule policy-type policy-action policy-match policy-value",
			dm: DNSMessage{DNSTap: DNSTap{PolicyRule: "rule", PolicyType: "type",
				PolicyAction: "action", PolicyMatch: "match",
				PolicyValue: "value"}},
			expected: "rule type action match value",
		},
		{
			format:   "peer-name",
			dm:       DNSMessage{DNSTap: DNSTap{PeerName: "testpeer"}},
			expected: "testpeer",
		},
		{
			format:   "query-zone",
			dm:       DNSMessage{DNSTap: DNSTap{QueryZone: "queryzone.test"}},
			expected: "queryzone.test",
		},
		{
			format:   "qdcount",
			dm:       DNSMessage{DNS: DNS{QdCount: 1}},
			expected: "1",
		},
		{
			format:   "ancount nscount arcount",
			dm:       DNSMessage{DNS: DNS{AnCount: 1, ArCount: 2, NsCount: 3}},
			expected: "1 3 2",
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

func TestDnsMessage_TextFormat_InvalidDirectives(t *testing.T) {
	testcases := []struct {
		name   string
		dm     DNSMessage
		format string
	}{
		{
			name:   "default",
			dm:     DNSMessage{},
			format: "invalid",
		},
		{
			name:   "publicsuffix",
			dm:     DNSMessage{PublicSuffix: &TransformPublicSuffix{}},
			format: "publixsuffix-invalid",
		},
		{
			name:   "powerdns",
			dm:     DNSMessage{PowerDNS: &PowerDNS{}},
			format: "powerdns-invalid",
		},
		{
			name:   "geoip",
			dm:     DNSMessage{Geo: &TransformDNSGeo{}},
			format: "geoip-invalid",
		},
		{
			name:   "suspicious",
			dm:     DNSMessage{Suspicious: &TransformSuspicious{}},
			format: "suspicious-invalid",
		},
		{
			name:   "extracted",
			dm:     DNSMessage{Extracted: &TransformExtracted{}},
			format: "extracted-invalid",
		},
		{
			name:   "filtering",
			dm:     DNSMessage{Filtering: &TransformFiltering{}},
			format: "filtering-invalid",
		},
		{
			name:   "reducer",
			dm:     DNSMessage{Reducer: &TransformReducer{}},
			format: "reducer-invalid",
		},
		{
			name:   "ml",
			dm:     DNSMessage{MachineLearning: &TransformML{}},
			format: "ml-invalid",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.dm.ToTextLine(strings.Fields(tc.format), " ", "")
			if err == nil {
				t.Errorf("Want err, got nil")
			} else if err.Error() != ErrorUnexpectedDirective+tc.format {
				t.Errorf("Unexpected error: %s", err.Error())
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_PublicSuffix(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "publixsuffix-tld",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "publixsuffix-tld publixsuffix-etld+1",
			dm:       DNSMessage{PublicSuffix: &TransformPublicSuffix{QnamePublicSuffix: "com", QnameEffectiveTLDPlusOne: "google.com"}},
			expected: "com google.com",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.dm.String(
				strings.Fields(tc.format),
				config.Global.TextFormatDelimiter,
				config.Global.TextFormatBoundary,
			)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Geo(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "geoip-continent",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:   "default",
			format: "geoip-continent geoip-country geoip-city geoip-as-number geoip-as-owner",
			dm: DNSMessage{Geo: &TransformDNSGeo{City: "Paris", Continent: "Europe",
				CountryIsoCode: "FR", AutonomousSystemNumber: "AS1", AutonomousSystemOrg: "Google"}},
			expected: "Europe FR Paris AS1 Google",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.dm.String(
				strings.Fields(tc.format),
				config.Global.TextFormatDelimiter,
				config.Global.TextFormatBoundary,
			)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Pdns(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "powerdns-tags",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "empty_attributes",
			format:   "powerdns-tags powerdns-applied-policy powerdns-original-request-subnet powerdns-metadata",
			dm:       DNSMessage{PowerDNS: &PowerDNS{}},
			expected: "- - - -",
		},
		{
			name:   "applied_policy",
			format: "powerdns-applied-policy powerdns-applied-policy-hit powerdns-applied-policy-kind powerdns-applied-policy-trigger powerdns-applied-policy-type",
			dm: DNSMessage{PowerDNS: &PowerDNS{
				AppliedPolicy:        "policy",
				AppliedPolicyHit:     "hit",
				AppliedPolicyKind:    "kind",
				AppliedPolicyTrigger: "trigger",
				AppliedPolicyType:    "type",
			}},
			expected: "policy hit kind trigger type",
		},
		{
			name:     "original_request_subnet",
			format:   "powerdns-original-request-subnet",
			dm:       DNSMessage{PowerDNS: &PowerDNS{OriginalRequestSubnet: "test"}},
			expected: "test",
		},
		{
			name:     "metadata_badsyntax",
			format:   "powerdns-metadata",
			dm:       DNSMessage{PowerDNS: &PowerDNS{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "-",
		},
		{
			name:     "metadata",
			format:   "powerdns-metadata:test_key1",
			dm:       DNSMessage{PowerDNS: &PowerDNS{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "test_value1",
		},
		{
			name:     "metadata_invalid",
			format:   "powerdns-metadata:test_key2",
			dm:       DNSMessage{PowerDNS: &PowerDNS{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "-",
		},
		{
			name:     "tags_all",
			format:   "powerdns-tags",
			dm:       DNSMessage{PowerDNS: &PowerDNS{Tags: []string{"tag1", "tag2"}}},
			expected: "tag1,tag2",
		},
		{
			name:     "tags_index",
			format:   "powerdns-tags:1",
			dm:       DNSMessage{PowerDNS: &PowerDNS{Tags: []string{"tag1", "tag2"}}},
			expected: "tag2",
		},
		{
			name:     "tags_invalid_index",
			format:   "powerdns-tags:3",
			dm:       DNSMessage{PowerDNS: &PowerDNS{Tags: []string{"tag1", "tag2"}}},
			expected: "-",
		},
		{
			name:     "message_id",
			format:   "powerdns-message-id",
			dm:       DNSMessage{PowerDNS: &PowerDNS{MessageID: "27c3e94ad6284eec9a50cfc5bd7384d6"}},
			expected: "27c3e94ad6284eec9a50cfc5bd7384d6",
		},
		{
			name:     "initial_requestor_id",
			format:   "powerdns-initial-requestor-id",
			dm:       DNSMessage{PowerDNS: &PowerDNS{InitialRequestorID: "5e006236c8a74f7eafc6af126e6d0689"}},
			expected: "5e006236c8a74f7eafc6af126e6d0689",
		},
		{
			name:     "requestor_id",
			format:   "powerdns-requestor-id",
			dm:       DNSMessage{PowerDNS: &PowerDNS{RequestorID: "5e006236c8a74f7eafc6af126e6d0689"}},
			expected: "5e006236c8a74f7eafc6af126e6d0689",
		},
		{
			name:     "device_id_name",
			format:   "powerdns-device-id powerdns-device-name",
			dm:       DNSMessage{PowerDNS: &PowerDNS{DeviceID: "5e006236c8a74f7eafc6af126e6d0689", DeviceName: "test"}},
			expected: "5e006236c8a74f7eafc6af126e6d0689 test",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.dm.String(
				strings.Fields(tc.format),
				config.Global.TextFormatDelimiter,
				config.Global.TextFormatBoundary,
			)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_ATags(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "atags",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "empty_attributes",
			format:   "atags",
			dm:       DNSMessage{ATags: &TransformATags{}},
			expected: "-",
		},
		{
			name:     "tags_all",
			format:   "atags",
			dm:       DNSMessage{ATags: &TransformATags{Tags: []string{"tag1", "tag2"}}},
			expected: "tag1,tag2",
		},
		{
			name:     "tags_index",
			format:   "atags:1",
			dm:       DNSMessage{ATags: &TransformATags{Tags: []string{"tag1", "tag2"}}},
			expected: "tag2",
		},
		{
			name:     "tags_invalid_index",
			format:   "atags:3",
			dm:       DNSMessage{ATags: &TransformATags{Tags: []string{"tag1", "tag2"}}},
			expected: "-",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.dm.String(
				strings.Fields(tc.format),
				config.Global.TextFormatDelimiter,
				config.Global.TextFormatBoundary,
			)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Suspicious(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "suspicious-score",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "suspicious-score",
			dm:       DNSMessage{Suspicious: &TransformSuspicious{Score: 4.0}},
			expected: "4",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.dm.String(
				strings.Fields(tc.format),
				config.Global.TextFormatDelimiter,
				config.Global.TextFormatBoundary,
			)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Reducer(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "reducer-occurrences",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "reducer-occurrences",
			dm:       DNSMessage{Reducer: &TransformReducer{Occurrences: 1}},
			expected: "1",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.dm.String(
				strings.Fields(tc.format),
				config.Global.TextFormatDelimiter,
				config.Global.TextFormatBoundary,
			)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Extracted(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "extracted-dns-payload",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:   "default",
			format: "extracted-dns-payload",
			dm: DNSMessage{Extracted: &TransformExtracted{}, DNS: DNS{Payload: []byte{
				0x9e, 0x84, 0x01, 0x20, 0x00, 0x03, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				// query 1
				0x01, 0x61, 0x00,
				// type A, class IN
				0x00, 0x01, 0x00, 0x01,
				// query 2
				0x01, 0x62, 0x00,
				// type A, class IN
				0x00, 0x01, 0x00, 0x01,
				// query 3
				0x01, 0x63, 0x00,
				// type AAAA, class IN
				0x00, 0x1c, 0x00, 0x01,
			}}},
			expected: "noQBIAADAAAAAAAAAWEAAAEAAQFiAAABAAEBYwAAHAAB",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.dm.String(
				strings.Fields(tc.format),
				config.Global.TextFormatDelimiter,
				config.Global.TextFormatBoundary,
			)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Filtering(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "filtering-sample-rate",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "filtering-sample-rate",
			dm:       DNSMessage{Filtering: &TransformFiltering{SampleRate: 22}},
			expected: "22",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.dm.String(
				strings.Fields(tc.format),
				config.Global.TextFormatDelimiter,
				config.Global.TextFormatBoundary,
			)
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func BenchmarkDnsMessage_ToTextFormat(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	textFormat := []string{"timestamp-rfc3339ns", "identity",
		"operation", "rcode", "queryip", "queryport", "family",
		"protocol", "length-unit", "qname", "qtype", "latency"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.ToTextLine(textFormat, " ", "\"")
		if err != nil {
			b.Fatalf("could not encode to text format: %v\n", err)
		}
	}
}
