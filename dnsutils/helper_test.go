package dnsutils

import (
	"strings"
	"testing"
)

func TestHelper_GetIPPort(t *testing.T) {
	tests := []struct {
		name        string
		dm          *DNSMessage
		wantSrcIP   string
		wantSrcPort int
		wantDstIP   string
		wantDstPort int
	}{
		{
			name: "Test IPv4 source and destination",
			dm: &DNSMessage{
				NetworkInfo: DNSNetInfo{
					Family:  "INET",
					QueryIP: "192.168.1.1", QueryPort: "1234",
					ResponseIP: "192.168.1.2", ResponsePort: "5678",
				},
				DNS: DNS{Type: DNSQuery},
			},
			wantSrcIP:   "192.168.1.1",
			wantSrcPort: 1234,
			wantDstIP:   "192.168.1.2",
			wantDstPort: 5678,
		},
		{
			name: "Test IPv6 source and destination",
			dm: &DNSMessage{
				NetworkInfo: DNSNetInfo{
					Family:  "INET6",
					QueryIP: "::1", QueryPort: "1234",
					ResponseIP: "::2", ResponsePort: "5678",
				},
				DNS: DNS{Type: DNSQuery},
			},
			wantSrcIP:   "::1",
			wantSrcPort: 1234,
			wantDstIP:   "::2",
			wantDstPort: 5678,
		},
		{
			name: "Test DNSReply type",
			dm: &DNSMessage{
				NetworkInfo: DNSNetInfo{
					Family:  "INET",
					QueryIP: "192.168.1.1", QueryPort: "1234",
					ResponseIP: "192.168.1.2", ResponsePort: "5678",
				},
				DNS: DNS{Type: DNSReply},
			},
			wantSrcIP:   "192.168.1.2",
			wantSrcPort: 5678,
			wantDstIP:   "192.168.1.1",
			wantDstPort: 1234,
		},
		{
			name: "Test missing QueryIP and ResponseIP",
			dm: &DNSMessage{
				NetworkInfo: DNSNetInfo{
					Family:  "INET",
					QueryIP: "-", QueryPort: "-",
					ResponseIP: "-", ResponsePort: "-",
				},
				DNS: DNS{Type: DNSQuery},
			},
			wantSrcIP:   "0.0.0.0",
			wantSrcPort: 53,
			wantDstIP:   "0.0.0.0",
			wantDstPort: 53,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP, srcPort, dstIP, dstPort := GetIPPort(tt.dm)
			if srcIP != tt.wantSrcIP {
				t.Errorf("GetIPPort() srcIP = %v, want %v", srcIP, tt.wantSrcIP)
			}
			if srcPort != tt.wantSrcPort {
				t.Errorf("GetIPPort() srcPort = %v, want %v", srcPort, tt.wantSrcPort)
			}
			if dstIP != tt.wantDstIP {
				t.Errorf("GetIPPort() dstIP = %v, want %v", dstIP, tt.wantDstIP)
			}
			if dstPort != tt.wantDstPort {
				t.Errorf("GetIPPort() dstPort = %v, want %v", dstPort, tt.wantDstPort)
			}
		})
	}
}

func TestHelper_ConvertToString(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "Test int",
			input:    42,
			expected: "42",
		},
		{
			name:     "Test bool true",
			input:    true,
			expected: "true",
		},
		{
			name:     "Test bool false",
			input:    false,
			expected: "false",
		},
		{
			name:     "Test float64",
			input:    3.14159,
			expected: "3.14159",
		},
		{
			name:     "Test string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "Test unknown type",
			input:    struct{ Name string }{Name: "example"},
			expected: "{example}",
		},
		{
			name:     "Test nil",
			input:    nil,
			expected: "<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertToString(tt.input)
			if result != tt.expected {
				t.Errorf("convertToString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHelper_QuoteStringAndWrite(t *testing.T) {
	tests := []struct {
		name           string
		fieldString    string
		fieldDelimiter string
		fieldBoundary  string
		expected       string
	}{
		{
			name:           "No delimiter, no boundary",
			fieldString:    "simpleString",
			fieldDelimiter: "",
			fieldBoundary:  "",
			expected:       "simpleString",
		},
		{
			name:           "Contains delimiter, no boundary",
			fieldString:    "string,with,commas",
			fieldDelimiter: ",",
			fieldBoundary:  "",
			expected:       "string,with,commas",
		},
		{
			name:           "Contains delimiter, with boundary",
			fieldString:    "string,with,commas",
			fieldDelimiter: ",",
			fieldBoundary:  "\"",
			expected:       "\"string,with,commas\"",
		},
		{
			name:           "Contains boundary, with delimiter",
			fieldString:    "string \"with\" quotes",
			fieldDelimiter: ",",
			fieldBoundary:  "\"",
			expected:       "\"string \\\"with\\\" quotes\"",
		},
		{
			name:           "Contains both delimiter and boundary",
			fieldString:    "string, \"with\" everything",
			fieldDelimiter: ",",
			fieldBoundary:  "\"",
			expected:       "\"string, \\\"with\\\" everything\"",
		},
		{
			name:           "Empty string with delimiter and boundary",
			fieldString:    "",
			fieldDelimiter: ",",
			fieldBoundary:  "\"",
			expected:       "\"\"",
		},
		{
			name:           "No delimiter, with boundary",
			fieldString:    "simpleString",
			fieldDelimiter: "",
			fieldBoundary:  "\"",
			expected:       "simpleString",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var builder strings.Builder
			QuoteStringAndWrite(&builder, tt.fieldString, tt.fieldDelimiter, tt.fieldBoundary)
			result := builder.String()

			if result != tt.expected {
				t.Errorf("quoteStringAndWrite() = %v, want %v", result, tt.expected)
			}
		})
	}
}
