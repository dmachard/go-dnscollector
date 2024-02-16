package dnsutils

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnstap-protobuf"
	"google.golang.org/protobuf/proto"
)

// Tests for DNSTap format
func encodeToDNSTap(dm DNSMessage, t *testing.T) *ExtendedDnstap {
	// encode to extended dnstap
	tapMsg, err := dm.ToDNSTap(true)
	if err != nil {
		t.Fatalf("could not encode to extended dnstap: %v\n", err)
	}

	// decode dnstap message
	dt := &dnstap.Dnstap{}
	err = proto.Unmarshal(tapMsg, dt)
	if err != nil {
		t.Fatalf("error to decode dnstap: %v", err)
	}

	// decode extended part
	edt := &ExtendedDnstap{}
	err = proto.Unmarshal(dt.GetExtra(), edt)
	if err != nil {
		t.Fatalf("error to decode extended dnstap: %v", err)
	}
	return edt
}

func TestDnsMessage_ToExtendedDNSTap_GetOriginalDnstapExtra(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.DNSTap.Extra = "tag0:value0"

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// check
	if string(edt.GetOriginalDnstapExtra()) != dm.DNSTap.Extra {
		t.Errorf("extra field should be equal to the original value")
	}
}

func TestDnsMessage_ToExtendedDNSTap_TransformAtags(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.ATags = &TransformATags{
		Tags: []string{"tag1:value1"},
	}

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// check
	if edt.GetAtags().Tags[0] != "tag1:value1" {
		t.Errorf("invalid value on atags")
	}
}

func TestDnsMessage_ToExtendedDNSTap_TransformNormalize(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.PublicSuffix = &TransformPublicSuffix{
		QnamePublicSuffix:        "com",
		QnameEffectiveTLDPlusOne: "dnscollector.com",
	}

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// checks
	if edt.GetNormalize().GetTld() != "com" {
		t.Errorf("invalid value on tld")
	}

	if edt.GetNormalize().GetEtldPlusOne() != "dnscollector.com" {
		t.Errorf("invalid value on etld+1")
	}
}

func TestDnsMessage_ToExtendedDNSTap_TransformFiltering(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.Filtering = &TransformFiltering{
		SampleRate: 20,
	}

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// checks
	if edt.GetFiltering().GetSampleRate() != 20 {
		t.Errorf("invalid value sample rate")
	}
}

func TestDnsMessage_ToExtendedDNSTap_TransformGeo(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.Geo = &TransformDNSGeo{
		City:                   "France",
		Continent:              "Europe",
		CountryIsoCode:         "44444",
		AutonomousSystemNumber: "3333",
		AutonomousSystemOrg:    "Test",
	}

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// checks
	if edt.GetGeo().GetCity() != "France" {
		t.Errorf("invalid value for city")
	}
	if edt.GetGeo().GetContinent() != "Europe" {
		t.Errorf("invalid value for continent")
	}
}

func TestDnsMessage_ToDNSTap(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.DNSTap.Extra = "extra:value"

	// encode to dnstap
	tapMsg, err := dm.ToDNSTap(false)
	if err != nil {
		t.Fatalf("could not encode to dnstap: %v\n", err)
	}

	// decode dnstap message
	dt := &dnstap.Dnstap{}
	err = proto.Unmarshal(tapMsg, dt)
	if err != nil {
		t.Fatalf("error to decode dnstap: %v", err)
	}

	if string(dt.GetIdentity()) != dm.DNSTap.Identity {
		t.Errorf("identify field should be equal got=%s", string(dt.GetIdentity()))
	}

	if string(dt.GetExtra()) != dm.DNSTap.Extra {
		t.Errorf("extra field should be equal got=%s", string(dt.GetExtra()))
	}
}

// Tests for JSON format
func TestDnsMessage_Json_Reference(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()

	refJSON := `
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
				  "id": 0,
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
					"ad": false,
					"rd": false,
					"cd": false
				  },
				  "resource-records": {
					"an": [],
					"ns": [],
					"ar": []
				  },
				  "malformed-packet": false
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
				  "latency": "-",
				  "extra": "-",
				  "policy-type": "-",
				  "policy-action": "-",
				  "policy-match": "-",
				  "policy-value": "-",
				  "policy-rule": "-",
				  "peer-name": "-"
				}
			}
			`

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJSON()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJSON), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if !reflect.DeepEqual(dmMap, refMap) {
		t.Errorf("json format different from reference")
	}
}

func TestDnsMessage_JsonFlatten_Reference(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()

	refJSON := `
				{
					"dns.flags.aa": false,
					"dns.flags.ad": false,
					"dns.flags.qr": false,
					"dns.flags.ra": false,
					"dns.flags.tc": false,
					"dns.flags.rd": false,
					"dns.flags.cd": false,
					"dns.length": 0,
					"dns.malformed-packet": false,
					"dns.id": 0,
					"dns.opcode": 0,
					"dns.qname": "-",
					"dns.qtype": "-",
					"dns.rcode": "-",
					"dns.resource-records.an": [],
					"dns.resource-records.ar": [],
					"dns.resource-records.ns": [],
					"dnstap.identity": "-",
					"dnstap.latency": "-",
					"dnstap.operation": "-",
					"dnstap.timestamp-rfc3339ns": "-",
					"dnstap.version": "-",
					"dnstap.extra": "-",
					"dnstap.policy-rule": "-",
					"dnstap.policy-type": "-",
					"dnstap.policy-action": "-",
					"dnstap.policy-match": "-",
					"dnstap.policy-value": "-",
					"dnstap.peer-name": "-",
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
	err = json.Unmarshal([]byte(refJSON), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if !reflect.DeepEqual(dmFlat, refMap) {
		t.Errorf("flatten json format different from reference")
	}
}

func TestDnsMessage_Json_Collectors_Reference(t *testing.T) {
	testcases := []struct {
		collector string
		dmRef     DNSMessage
		jsonRef   string
	}{
		{
			collector: "powerdns",
			dmRef: DNSMessage{PowerDNS: &PowerDNS{
				OriginalRequestSubnet: "subnet",
				AppliedPolicy:         "basicrpz",
				AppliedPolicyHit:      "hit",
				AppliedPolicyKind:     "kind",
				AppliedPolicyTrigger:  "trigger",
				AppliedPolicyType:     "type",
				Tags:                  []string{"tag1"},
				Metadata:              map[string]string{"stream_id": "collector"},
				HTTPVersion:           "http3",
			}},

			jsonRef: `{
						"powerdns": {
							"original-request-subnet": "subnet",
							"applied-policy": "basicrpz",
							"applied-policy-hit": "hit",
							"applied-policy-kind": "kind",
							"applied-policy-trigger": "trigger",
							"applied-policy-type": "type",
							"tags": ["tag1"],
							"metadata": {
								"stream_id": "collector"
							},
							"http-version": "http3"
						}
					}`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.collector, func(t *testing.T) {

			tc.dmRef.Init()

			var dmMap map[string]interface{}
			err := json.Unmarshal([]byte(tc.dmRef.ToJSON()), &dmMap)
			if err != nil {
				t.Fatalf("could not unmarshal dm json: %s\n", err)
			}

			var refMap map[string]interface{}
			err = json.Unmarshal([]byte(tc.jsonRef), &refMap)
			if err != nil {
				t.Fatalf("could not unmarshal ref json: %s\n", err)
			}

			if !reflect.DeepEqual(dmMap[tc.collector], refMap[tc.collector]) {
				t.Errorf("json format different from reference, Get=%s Want=%s", dmMap[tc.collector], refMap[tc.collector])
			}
		})
	}
}

func TestDnsMessage_Json_Transforms_Reference(t *testing.T) {

	testcases := []struct {
		transform string
		dmRef     DNSMessage
		jsonRef   string
	}{
		{
			transform: "filtering",
			dmRef:     DNSMessage{Filtering: &TransformFiltering{SampleRate: 22}},
			jsonRef: `{
						"filtering": {
						"sample-rate": 22
						}
					}`,
		},
		{
			transform: "reducer",
			dmRef:     DNSMessage{Reducer: &TransformReducer{Occurrences: 10, CumulativeLength: 47}},
			jsonRef: `{
						"reducer": {
							"occurrences": 10,
							"cumulative-length": 47
						}
					}`,
		},
		{
			transform: "normalize",
			dmRef: DNSMessage{
				PublicSuffix: &TransformPublicSuffix{
					QnamePublicSuffix:        "com",
					QnameEffectiveTLDPlusOne: "hello.com",
				},
			},
			jsonRef: `{
						"publicsuffix": {
							"tld": "com",
							"etld+1": "hello.com"
						}
					}`,
		},
		{
			transform: "geoip",
			dmRef: DNSMessage{
				Geo: &TransformDNSGeo{
					City:                   "Paris",
					Continent:              "Europe",
					CountryIsoCode:         "FR",
					AutonomousSystemNumber: "1234",
					AutonomousSystemOrg:    "Internet",
				},
			},
			jsonRef: `{
						"geoip": {
							"city": "Paris",
							"continent": "Europe",
							"country-isocode": "FR",
							"as-number": "1234",
							"as-owner": "Internet"
						}
					}`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.transform, func(t *testing.T) {

			tc.dmRef.Init()

			var dmMap map[string]interface{}
			err := json.Unmarshal([]byte(tc.dmRef.ToJSON()), &dmMap)
			if err != nil {
				t.Fatalf("could not unmarshal dm json: %s\n", err)
			}

			var refMap map[string]interface{}
			err = json.Unmarshal([]byte(tc.jsonRef), &refMap)
			if err != nil {
				t.Fatalf("could not unmarshal ref json: %s\n", err)
			}

			if !reflect.DeepEqual(dmMap[tc.transform], refMap[tc.transform]) {
				t.Errorf("json format different from reference, Get=%s Want=%s", dmMap[tc.transform], refMap[tc.transform])
			}
		})
	}
}

// Tests for TEXT format
func TestDnsMessage_TextFormat_ToString(t *testing.T) {

	config := pkgconfig.GetFakeConfig()

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
			dm := DNSMessage{}
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
	config := pkgconfig.GetFakeConfig()

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
			dm:       DNSMessage{DNSTap: DNSTap{LatencySec: "0.00001"}},
			expected: "0.00001",
		},
		{
			format:   "qname qtype opcode",
			dm:       DNSMessage{DNS: DNS{Qname: "dnscollector.fr", Qtype: "AAAA", Opcode: 42}},
			expected: "dnscollector.fr AAAA 42",
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
	config := pkgconfig.GetFakeConfig()

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
	config := pkgconfig.GetFakeConfig()

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
	config := pkgconfig.GetFakeConfig()

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
			name:     "http_version",
			format:   "powerdns-http-version",
			dm:       DNSMessage{PowerDNS: &PowerDNS{HTTPVersion: "HTTP2"}},
			expected: "HTTP2",
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
	config := pkgconfig.GetFakeConfig()

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
	config := pkgconfig.GetFakeConfig()

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
	config := pkgconfig.GetFakeConfig()

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
	config := pkgconfig.GetFakeConfig()

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
