package dnsutils

import "testing"

// Matching
func TestDNSMessage_Matching(t *testing.T) {
	tests := []struct {
		name      string
		dm        *DNSMessage
		matching  map[string]interface{}
		wantError bool
		wantMatch bool
	}{
		{
			name:      "Test integer matching",
			dm:        &DNSMessage{DNS: DNS{Opcode: 1}},
			matching:  map[string]interface{}{"dns.opcode": 1},
			wantError: false,
			wantMatch: true,
		},
		{
			name:      "Test no match with incorrect integer",
			dm:        &DNSMessage{DNS: DNS{Opcode: 2}},
			matching:  map[string]interface{}{"dns.opcode": 1},
			wantError: false,
			wantMatch: false,
		},
		{
			name:      "Test string matching",
			dm:        &DNSMessage{DNS: DNS{Qname: "www.example.com"}},
			matching:  map[string]interface{}{"dns.qname": "www.example.com"},
			wantError: false,
			wantMatch: true,
		},
		{
			name:      "Test no match with incorrect string",
			dm:        &DNSMessage{DNS: DNS{Qname: "www.notexample.com"}},
			matching:  map[string]interface{}{"dns.qname": "www.example.com"},
			wantError: false,
			wantMatch: false,
		},
		{
			name:      "Test boolean matching",
			dm:        &DNSMessage{DNS: DNS{Flags: DNSFlags{QR: true}}},
			matching:  map[string]interface{}{"dns.flags.qr": true},
			wantError: false,
			wantMatch: true,
		},
		{
			name:      "Test no match with incorrect boolean",
			dm:        &DNSMessage{DNS: DNS{Flags: DNSFlags{QR: false}}},
			matching:  map[string]interface{}{"dns.flags.qr": true},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test regex with match",
			dm:   &DNSMessage{DNS: DNS{Qname: "www.github.com"}},
			matching: map[string]interface{}{
				"dns.qname": "^.*\\.github\\.com$",
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test regex with no match",
			dm:   &DNSMessage{DNS: DNS{Qname: "www.google.com"}},
			matching: map[string]interface{}{
				"dns.qname": "^.*\\.github\\.com$",
			},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test matching with multiple conditions",
			dm:   &DNSMessage{DNS: DNS{Opcode: 1, Qname: "www.example.com", Flags: DNSFlags{QR: true}}},
			matching: map[string]interface{}{
				"dns.flags.qr": true,
				"dns.opcode":   1,
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test integer greater than operator matching",
			dm:   &DNSMessage{DNS: DNS{Opcode: 5}},
			matching: map[string]interface{}{
				"dns.opcode": map[string]interface{}{
					"greater-than": 3,
				},
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test integer with invalid greater than operator",
			dm:   &DNSMessage{DNS: DNS{Opcode: 1}},
			matching: map[string]interface{}{
				"dns.opcode": map[string]interface{}{
					"greater-than": "0",
				},
			},
			wantError: true,
			wantMatch: false,
		},
		{
			name: "Test float greater than operator matching",
			dm:   &DNSMessage{DNSTap: DNSTap{Latency: 0.5}},
			matching: map[string]interface{}{
				"dnstap.latency": map[string]interface{}{
					"greater-than": 0.3,
				},
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test lower than operator matching",
			dm:   &DNSMessage{DNS: DNS{Opcode: 9}},
			matching: map[string]interface{}{
				"dns.opcode": map[string]interface{}{
					"lower-than": 10,
				},
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test lower than operator no match",
			dm:   &DNSMessage{DNS: DNS{Opcode: 1}},
			matching: map[string]interface{}{
				"dns.opcode": map[string]interface{}{
					"lower-than": 1,
				},
			},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test  no match invalid lower than operator",
			dm:   &DNSMessage{DNS: DNS{Opcode: 1}},
			matching: map[string]interface{}{
				"dns.opcode": map[string]interface{}{
					"lower-than": "1",
				},
			},
			wantError: true,
			wantMatch: false,
		},
		{
			name: "Test match with list of string",
			dm:   &DNSMessage{DNS: DNS{Qname: "www.example.com"}},
			matching: map[string]interface{}{
				"dns.qname": []interface{}{"www.test.com", "www.example.com"},
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test no match with list of string",
			dm:   &DNSMessage{DNS: DNS{Qname: "www.notexample.com"}},
			matching: map[string]interface{}{
				"dns.qname": []interface{}{"www.test.com", "www.example.com"},
			},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test non-existent key",
			dm:   &DNSMessage{DNS: DNS{Opcode: 1}},
			matching: map[string]interface{}{
				"dns.nonexistent": 1,
			},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test nested non-existent key",
			dm:   &DNSMessage{DNS: DNS{Opcode: 1}},
			matching: map[string]interface{}{
				"dns.flags.nonexistent": true,
			},
			wantError: false,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, isMatch := tt.dm.Matching(tt.matching)
			if (err != nil) != tt.wantError {
				t.Errorf("DNSMessage.Matching() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if isMatch != tt.wantMatch {
				t.Errorf("DNSMessage.Matching() = %v, want %v", isMatch, tt.wantMatch)
			}
		})
	}
}

func TestDNSMessage_Matching_Arrays(t *testing.T) {
	tests := []struct {
		name      string
		dm        *DNSMessage
		matching  map[string]interface{}
		wantError bool
		wantMatch bool
	}{
		{
			name: "Test wilcard match with operator",
			dm:   &DNSMessage{DNS: DNS{DNSRRs: DNSRRs{Answers: []DNSAnswer{{TTL: 300}}}}},
			matching: map[string]interface{}{
				"dns.resource-records.an.*.ttl": map[string]interface{}{
					"greater-than": 10,
				},
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test wilcard no match and operator",
			dm:   &DNSMessage{DNS: DNS{DNSRRs: DNSRRs{Answers: []DNSAnswer{{TTL: 300}}}}},
			matching: map[string]interface{}{
				"dns.resource-records.an.*.ttl": map[string]interface{}{
					"greater-than": 400,
				},
			},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test wilcard no match and invalid operator",
			dm:   &DNSMessage{DNS: DNS{DNSRRs: DNSRRs{Answers: []DNSAnswer{{TTL: 300}}}}},
			matching: map[string]interface{}{
				"dns.resource-records.an.*.ttl": map[string]interface{}{
					"greater-than-invalid": 400,
				},
			},
			wantError: true,
			wantMatch: false,
		},
		{
			name: "Test array match with index",
			dm:   &DNSMessage{DNS: DNS{DNSRRs: DNSRRs{Answers: []DNSAnswer{{TTL: 300}}}}},
			matching: map[string]interface{}{
				"dns.resource-records.an.0.ttl": 300,
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test array match with invalid index",
			dm:   &DNSMessage{DNS: DNS{DNSRRs: DNSRRs{Answers: []DNSAnswer{{TTL: 300}}}}},
			matching: map[string]interface{}{
				"dns.resource-records.an.1.ttl": 300,
			},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test array match with index and multiple conditions",
			dm: &DNSMessage{
				DNSTap: DNSTap{Operation: "CLIENT_RESPONSE"},
				DNS:    DNS{Rcode: "NOERROR", Qtype: "A", DNSRRs: DNSRRs{Answers: []DNSAnswer{{Rdata: "0.0.0.0"}}}},
			},
			matching: map[string]interface{}{
				"dnstap.operation":                "CLIENT_RESPONSE",
				"dns.qtype":                       "A",
				"dns.rcode":                       "NOERROR",
				"dns.resource-records.an.0.rdata": "0.0.0.0",
			},
			wantError: false,
			wantMatch: true,
		},
		{
			name: "Test array match with index and missing key",
			dm:   &DNSMessage{DNS: DNS{DNSRRs: DNSRRs{Answers: []DNSAnswer{{TTL: 300}}}}},
			matching: map[string]interface{}{
				"dns.resource-records.an.0.missing-key": 300,
			},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test array match with bad index",
			dm:   &DNSMessage{DNS: DNS{DNSRRs: DNSRRs{Answers: []DNSAnswer{{TTL: 300}}}}},
			matching: map[string]interface{}{
				"dns.resource-records.an.badindex.ttl": 300,
			},
			wantError: false,
			wantMatch: false,
		},
		{
			name: "Test array no match with index and invalid data type",
			dm:   &DNSMessage{DNS: DNS{DNSRRs: DNSRRs{Answers: []DNSAnswer{{TTL: 300}}}}},
			matching: map[string]interface{}{
				"dns.resource-records.an.0.ttl": "not-a-number",
			},
			wantError: false,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, isMatch := tt.dm.Matching(tt.matching)
			if (err != nil) != tt.wantError {
				t.Errorf("DNSMessage.Matching() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if isMatch != tt.wantMatch {
				t.Errorf("DNSMessage.Matching() = %v, want %v", isMatch, tt.wantMatch)
			}
		})
	}
}
