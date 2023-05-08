package dnsutils

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDnsMessage_Json_Reference(t *testing.T) {
	dm := DnsMessage{}
	dm.Init()

	refJson := `
			{
				"network": {
				  "family": "-",
				  "protocol": "-",
				  "query-ip": "-",
				  "query-port": "-",
				  "response-ip": "-",
				  "response-port": "-",
				  "ip-defragmented": false,
				  "tcp-reassembled": false
				},
				"dns": {
				  "length": 0,
				  "opcode": 0,
				  "rcode": "-",
				  "qname": "-",
				  "qtype": "-",
				  "flags": {
					"qr": false,
					"tc": false,
					"aa": false,
					"ra": false,
					"ad": false
				  },
				  "resource-records": {
					"an": [],
					"ns": [],
					"ar": []
				  },
				  "malformed-packet": false,
				  "repeated": -1
				},
				"edns": {
				  "udp-size": 0,
				  "rcode": 0,
				  "version": 0,
				  "dnssec-ok": 0,
				  "options": []
				},
				"dnstap": {
				  "operation": "-",
				  "identity": "-",
				  "version": "-",
				  "timestamp-rfc3339ns": "-",
				  "latency": "-"
				}
			}
			`

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJson()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJson), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if !reflect.DeepEqual(dmMap, refMap) {
		t.Fail()
	}

}

func TestDnsMessage_Json_Flatten_Reference(t *testing.T) {
	dm := DnsMessage{}
	dm.Init()

	refJson := `
				{
					"dns.flags.aa": false,
					"dns.flags.ad": false,
					"dns.flags.qr": false,
					"dns.flags.ra": false,
					"dns.flags.tc": false,
					"dns.length": 0,
					"dns.malformed-packet": false,
					"dns.opcode": 0,
					"dns.qname": "-",
					"dns.qtype": "-",
					"dns.rcode": "-",
					"dns.repeated": -1,
					"dns.resource-records.an": [],
					"dns.resource-records.ar": [],
					"dns.resource-records.ns": [],
					"dnstap.identity": "-",
					"dnstap.latency": "-",
					"dnstap.operation": "-",
					"dnstap.timestamp-rfc3339ns": "-",
					"dnstap.version": "-",
					"edns.dnssec-ok": 0,
					"edns.options": [],
					"edns.rcode": 0,
					"edns.udp-size": 0,
					"edns.version": 0,
					"network.family": "-",
					"network.ip-defragmented": false,
					"network.protocol": "-",
					"network.query-ip": "-",
					"network.query-port": "-",
					"network.response-ip": "-",
					"network.response-port": "-",
					"network.tcp-reassembled": false
				}
			`

	dmFlat, err := dm.Flatten()
	if err != nil {
		t.Fatalf("could not flat json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJson), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if !reflect.DeepEqual(dmFlat, refMap) {
		t.Fail()
	}

}

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

func TestDnsMessage_TextFormat_Directives_PublicSuffix(t *testing.T) {
	config := GetFakeConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DnsMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "publixsuffix-tld",
			dm:       DnsMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "publixsuffix-tld publixsuffix-etld+1",
			dm:       DnsMessage{PublicSuffix: &PublicSuffix{QnamePublicSuffix: "com", QnameEffectiveTLDPlusOne: "google.com"}},
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
	config := GetFakeConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DnsMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "geoip-continent",
			dm:       DnsMessage{},
			expected: "-",
		},
		{
			name:   "default",
			format: "geoip-continent geoip-country geoip-city geoip-as-number geoip-as-owner",
			dm: DnsMessage{Geo: &DnsGeo{City: "Paris", Continent: "Europe",
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
	config := GetFakeConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DnsMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "powerdns-tags",
			dm:       DnsMessage{},
			expected: "-",
		},
		{
			name:     "empty_attributes",
			format:   "powerdns-tags powerdns-applied-policy powerdns-original-request-subnet powerdns-metadata",
			dm:       DnsMessage{PowerDns: &PowerDns{}},
			expected: "- - - -",
		},
		{
			name:     "applied_policy",
			format:   "powerdns-applied-policy",
			dm:       DnsMessage{PowerDns: &PowerDns{AppliedPolicy: "test"}},
			expected: "test",
		},
		{
			name:     "original_request_subnet",
			format:   "powerdns-original-request-subnet",
			dm:       DnsMessage{PowerDns: &PowerDns{OriginalRequestSubnet: "test"}},
			expected: "test",
		},
		{
			name:     "metadata_badsyntax",
			format:   "powerdns-metadata",
			dm:       DnsMessage{PowerDns: &PowerDns{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "-",
		},
		{
			name:     "metadata",
			format:   "powerdns-metadata:test_key1",
			dm:       DnsMessage{PowerDns: &PowerDns{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "test_value1",
		},
		{
			name:     "metadata_invalid",
			format:   "powerdns-metadata:test_key2",
			dm:       DnsMessage{PowerDns: &PowerDns{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "-",
		},
		{
			name:     "tags_all",
			format:   "powerdns-tags",
			dm:       DnsMessage{PowerDns: &PowerDns{Tags: []string{"tag1", "tag2"}}},
			expected: "tag1,tag2",
		},
		{
			name:     "tags_index",
			format:   "powerdns-tags:1",
			dm:       DnsMessage{PowerDns: &PowerDns{Tags: []string{"tag1", "tag2"}}},
			expected: "tag2",
		},
		{
			name:     "tags_invalid_index",
			format:   "powerdns-tags:3",
			dm:       DnsMessage{PowerDns: &PowerDns{Tags: []string{"tag1", "tag2"}}},
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
	config := GetFakeConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DnsMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "suspicious-score",
			dm:       DnsMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "suspicious-score",
			dm:       DnsMessage{Suspicious: &Suspicious{Score: 4.0}},
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

func TestDnsMessage_TextFormat_Directives_Extracted(t *testing.T) {
	config := GetFakeConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DnsMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "extracted-dns-payload",
			dm:       DnsMessage{},
			expected: "-",
		},
		{
			name:   "default",
			format: "extracted-dns-payload",
			dm: DnsMessage{Extracted: &Extracted{}, DNS: Dns{Payload: []byte{
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
