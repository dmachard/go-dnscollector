package dnsutils

import (
	"encoding/json"
	"reflect"
	"testing"
)

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
				  "qclass": "-",
				  "qdcount": 0,
				  "ancount": 0,
				  "nscount": 0,
				  "arcount": 0,
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
				  "latency": 0,
				  "extra": "-",
				  "policy-type": "-",
				  "policy-action": "-",
				  "policy-match": "-",
				  "policy-value": "-",
				  "policy-rule": "-",
				  "peer-name": "-",
				  "query-zone": "-"
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
		t.Errorf("json format different from reference %v", dmMap)
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
				MessageID:             "27c3e94ad6284eec9a50cfc5bd7384d6",
				InitialRequestorID:    "5e006236c8a74f7eafc6af126e6d0689",
				RequestorID:           "f7c3e94ad6284eec9a50cfc5bd7384d6",
				DeviceId:              "ffffffffffffffffeaaeaeae",
				DeviceName:            "foobar",
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
							"http-version": "http3",
							"message-id": "27c3e94ad6284eec9a50cfc5bd7384d6",
							"initial-requestor-id": "5e006236c8a74f7eafc6af126e6d0689",
							"requestor-id": "f7c3e94ad6284eec9a50cfc5bd7384d6",
							"device-id": "ffffffffffffffffeaaeaeae",
							"device-name": "foobar"
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
					ManagedByICANN:           true,
				},
			},
			jsonRef: `{
						"publicsuffix": {
							"tld": "com",
							"etld+1": "hello.com",
							"managed-icann": true
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
		{
			transform: "atags",
			dmRef:     DNSMessage{ATags: &TransformATags{Tags: []string{"test0", "test1"}}},
			jsonRef: `{
						"atags": {
							"tags": [ "test0", "test1" ]
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

func BenchmarkDnsMessage_ToJSON(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.ToJSON()
	}
}

// Tests for Flat JSON format
func TestDnsMessage_JsonFlatten_Reference(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()

	// add some items in slices field
	dm.DNS.DNSRRs.Answers = append(dm.DNS.DNSRRs.Answers, DNSAnswer{Name: "google.nl", Rdata: "142.251.39.99", Rdatatype: "A", TTL: 300, Class: "IN"})
	dm.EDNS.Options = append(dm.EDNS.Options, DNSOption{Code: 10, Data: "aaaabbbbcccc", Name: "COOKIE"})

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
					"dns.qclass": "-",
					"dns.qdcount": 0,
					"dns.ancount": 0,
					"dns.arcount": 0,
					"dns.nscount": 0,
					"dns.resource-records.an.0.name": "google.nl",
					"dns.resource-records.an.0.rdata": "142.251.39.99",
					"dns.resource-records.an.0.rdatatype": "A",
					"dns.resource-records.an.0.ttl": 300,
					"dns.resource-records.an.0.class": "IN",
					"dns.resource-records.ar": "-",
					"dns.resource-records.ns": "-",
					"dnstap.identity": "-",
					"dnstap.latency": 0,
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
					"dnstap.query-zone": "-",
					"edns.dnssec-ok": 0,
					"edns.options.0.code": 10,
					"edns.options.0.data": "aaaabbbbcccc",
					"edns.options.0.name": "COOKIE",
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

	var dmFlat map[string]interface{}
	dmJSON, err := dm.ToFlatJSON()
	if err != nil {
		t.Fatalf("could not convert dm to flat json: %s\n", err)
	}
	err = json.Unmarshal([]byte(dmJSON), &dmFlat)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJSON), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	for k, vRef := range refMap {
		vFlat, ok := dmFlat[k]
		if !ok {
			t.Fatalf("Missing key %s in flatten message according to reference", k)
		}
		if vRef != vFlat {
			t.Errorf("Invalid value for key=%s get=%v expected=%v", k, vFlat, vRef)
		}
	}

	for k := range dmFlat {
		_, ok := refMap[k]
		if !ok {
			t.Errorf("This key %s should not be in the flat message", k)
		}
	}
}

func TestDnsMessage_JsonFlatten_Transforms_Reference(t *testing.T) {

	testcases := []struct {
		transform string
		dm        DNSMessage
		jsonRef   string
	}{
		{
			transform: "filtering",
			dm:        DNSMessage{Filtering: &TransformFiltering{SampleRate: 22}},
			jsonRef: `{
						"filtering.sample-rate": 22
					  }`,
		},
		{
			transform: "reducer",
			dm:        DNSMessage{Reducer: &TransformReducer{Occurrences: 10, CumulativeLength: 47}},
			jsonRef: `{
						"reducer.occurrences": 10,
						"reducer.cumulative-length": 47
					  }`,
		},
		{
			transform: "publixsuffix",
			dm: DNSMessage{
				PublicSuffix: &TransformPublicSuffix{
					QnamePublicSuffix:        "com",
					QnameEffectiveTLDPlusOne: "hello.com",
				},
			},
			jsonRef: `{
						"publicsuffix.tld": "com",
						"publicsuffix.etld+1": "hello.com"
					  }`,
		},
		{
			transform: "geoip",
			dm: DNSMessage{
				Geo: &TransformDNSGeo{
					City:                   "Paris",
					Continent:              "Europe",
					CountryIsoCode:         "FR",
					AutonomousSystemNumber: "1234",
					AutonomousSystemOrg:    "Internet",
				},
			},
			jsonRef: `{
						"geoip.city": "Paris",
						"geoip.continent": "Europe",
						"geoip.country-isocode": "FR",
						"geoip.as-number": "1234",
						"geoip.as-owner": "Internet"
					}`,
		},
		{
			transform: "suspicious",
			dm: DNSMessage{Suspicious: &TransformSuspicious{Score: 1.0,
				MalformedPacket:       false,
				LargePacket:           true,
				LongDomain:            true,
				SlowDomain:            false,
				UnallowedChars:        true,
				UncommonQtypes:        false,
				ExcessiveNumberLabels: true,
				Domain:                "gogle.co",
			}},
			jsonRef: `{
						"suspicious.score": 1.0,
						"suspicious.malformed-pkt": false,
						"suspicious.large-pkt": true,
						"suspicious.long-domain": true,
						"suspicious.slow-domain": false,
						"suspicious.unallowed-chars": true,
						"suspicious.uncommon-qtypes": false,
						"suspicious.excessive-number-labels": true,
						"suspicious.domain": "gogle.co"
					  }`,
		},
		{
			transform: "extracted",
			dm:        DNSMessage{Extracted: &TransformExtracted{Base64Payload: []byte{}}},
			jsonRef: `{
						"extracted.dns_payload": ""
					  }`,
		},
		{
			transform: "machinelearning",
			dm: DNSMessage{MachineLearning: &TransformML{
				Entropy:               10.0,
				Length:                2,
				Labels:                2,
				Digits:                1,
				Lowers:                35,
				Uppers:                23,
				Specials:              2,
				Others:                1,
				RatioDigits:           1.0,
				RatioLetters:          1.0,
				RatioSpecials:         1.0,
				RatioOthers:           1.0,
				ConsecutiveChars:      10,
				ConsecutiveVowels:     10,
				ConsecutiveDigits:     10,
				ConsecutiveConsonants: 10,
				Size:                  11,
				Occurrences:           10,
				UncommonQtypes:        1,
			}},
			jsonRef: `{
						"ml.entropy": 10.0,
						"ml.length": 2,
						"ml.labels": 2,
						"ml.digits": 1,
						"ml.lowers": 35,
						"ml.uppers": 23,
						"ml.specials": 2,
						"ml.others": 1,
						"ml.ratio-digits": 1.0,
						"ml.ratio-letters": 1.0,
						"ml.ratio-specials": 1.0,
						"ml.ratio-others": 1.0,
						"ml.consecutive-chars": 10,
						"ml.consecutive-vowels": 10,
						"ml.consecutive-digits": 10,
						"ml.consecutive-consonants": 10,
						"ml.size": 11,
						"ml.occurrences": 10,
						"ml.uncommon-qtypes": 1
					  }`,
		},
		{
			transform: "atags",
			dm:        DNSMessage{ATags: &TransformATags{Tags: []string{"test0", "test1"}}},
			jsonRef: `{
						"atags.tags.0": "test0",
						"atags.tags.1": "test1"
					  }`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.transform, func(t *testing.T) {

			tc.dm.Init()

			var dmFlat map[string]interface{}
			dmJSON, err := tc.dm.ToFlatJSON()
			if err != nil {
				t.Fatalf("could not convert dm to flat json: %s\n", err)
			}
			err = json.Unmarshal([]byte(dmJSON), &dmFlat)
			if err != nil {
				t.Fatalf("could not unmarshal dm json: %s\n", err)
			}

			var refMap map[string]interface{}
			err = json.Unmarshal([]byte(tc.jsonRef), &refMap)
			if err != nil {
				t.Fatalf("could not unmarshal ref json: %s\n", err)
			}

			for k, vRef := range refMap {
				vFlat, ok := dmFlat[k]
				if !ok {
					t.Fatalf("Missing key %s in flatten message according to reference", k)
				}
				if vRef != vFlat {
					t.Errorf("Invalid value for key=%s get=%v expected=%v", k, vFlat, vRef)
				}
			}
		})
	}
}

func TestDnsMessage_JsonFlatten_Collectors_Reference(t *testing.T) {
	testcases := []struct {
		collector string
		dm        DNSMessage
		jsonRef   string
	}{
		{
			collector: "powerdns",
			dm: DNSMessage{PowerDNS: &PowerDNS{
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
						"powerdns.original-request-subnet": "subnet",
						"powerdns.applied-policy": "basicrpz",
						"powerdns.applied-policy-hit": "hit",
						"powerdns.applied-policy-kind": "kind",
						"powerdns.applied-policy-trigger": "trigger",
						"powerdns.applied-policy-type": "type",
						"powerdns.tags.0": "tag1",
						"powerdns.metadata.stream_id": "collector",
						"powerdns.http-version": "http3"
					}`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.collector, func(t *testing.T) {

			tc.dm.Init()

			var dmFlat map[string]interface{}
			dmJSON, err := tc.dm.ToFlatJSON()
			if err != nil {
				t.Fatalf("could not convert dm to flat json: %s\n", err)
			}
			err = json.Unmarshal([]byte(dmJSON), &dmFlat)
			if err != nil {
				t.Fatalf("could not unmarshal dm json: %s\n", err)
			}

			var refMap map[string]interface{}
			err = json.Unmarshal([]byte(tc.jsonRef), &refMap)
			if err != nil {
				t.Fatalf("could not unmarshal ref json: %s\n", err)
			}

			for k, vRef := range refMap {
				vFlat, ok := dmFlat[k]
				if !ok {
					t.Fatalf("Missing key %s in flatten message according to reference", k)
				}
				if vRef != vFlat {
					t.Errorf("Invalid value for key=%s get=%v expected=%v", k, vFlat, vRef)
				}
			}
		})
	}
}

func BenchmarkDnsMessage_ToFlatJSON(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.ToFlatJSON()
		if err != nil {
			b.Fatalf("could not encode to flat json: %v\n", err)
		}
	}
}
