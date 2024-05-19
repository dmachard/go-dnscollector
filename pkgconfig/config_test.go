package pkgconfig

import (
	"os"
	"testing"
)

// ServerIdentity is set in the config
func TestConfig_GetServerIdentity(t *testing.T) {
	config := &Config{
		Global: ConfigGlobal{
			ServerIdentity: "test-server",
		},
	}
	expected1 := "test-server"
	if result1 := config.GetServerIdentity(); result1 != expected1 {
		t.Errorf("Expected %s, but got %s", expected1, result1)
	}
}

// ServerIdentity is not set in the config, hostname is available
func TestConfig_GetServerIdentity_Hostname(t *testing.T) {
	config := &Config{
		Global: ConfigGlobal{},
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal("Error getting hostname:", err)
	}
	expected2 := hostname
	if result2 := config.GetServerIdentity(); result2 != expected2 {
		t.Errorf("Expected %s, but got %s", expected2, result2)
	}
}

func createTempConfigFile(content string) (string, error) {
	tempFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	if _, err := tempFile.WriteString(content); err != nil {
		return "", err
	}

	return tempFile.Name(), nil
}

func TestConfig_CheckConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "Valid multiplexer configuration",
			content: `
global:
  trace:
    verbose: true
  server-identity: "dns-collector"
multiplexer:
  collectors:
    - name: tap
      dnstap:
        listen-ip: 0.0.0.0
        listen-port: 6000
      transforms:
        normalize:
          qname-lowercase: false
  loggers:
    - name: console
      stdout:
        mode: text
  routes:
    - from: [ tap ]
      to: [ console ]
`,
			wantErr: false,
		},
		{
			name: "Valid pipeline configuration",
			content: `
global:
  trace:
    verbose: true
  server-identity: "dns-collector"
pipelines:
  - name: dnsdist-main
    dnstap:
      listen-ip: 0.0.0.0
      listen-port: 6000
    routing-policy: 
      default: [ console ]

  - name: console
    stdout:
      mode: text
`,
			wantErr: false,
		},
		{
			name: "Invalid key",
			content: `
global:
  logger: bad-position
`,
			wantErr: true,
		},
		{
			name: "Invalid multiplexer config format",
			content: `
multiplexer:
  - name: block
    dnstap:
      listen-ip: 0.0.0.0
    transforms:
      normalize:
        qname-lowercase: true
`,
			wantErr: true,
		},
		{
			name: "Invalid multiplexer logger",
			content: `
multiplexer:
  collectors:
  - name: tap
    dnstap:
      listen-ip: 0.0.0.0
  loggers:
  - name: tapOut
    dnstap:
      listen-ip: 0.0.0.0
  routes:
  - from: [ tapIn ]
    to: [ tapOut ]
`,
			wantErr: true,
		},
		{
			name: "Invalid pipeline transform",
			content: `
pipelines:
  - name: dnsdist-main
    dnstap:
      listen-ip: 0.0.0.0
      transforms:
        normalize:
          qname-lowercase: true
    routing-policy: 
      default: [ console ]
`,
			wantErr: true,
		},
		{
			name: "Invalid multiplexer route",
			content: `
multiplexer:
  routes:
  - from: [test-route]
    unknown-key: invalid
`,
			wantErr: true,
		},
		{
			name: "pipeline dynamic keys",
			content: `
pipelines:
  - name: match
    dnsmessage:
      matching:
        include:
          atags.tags.*: test
          atags.tags.2: test
          dns.resources-records.*: test
`,
			wantErr: false,
		},
		{
			name: "freeform loki #643",
			content: `
multiplexer:
  collectors:
  - name: tap
    dnstap:
      listen-ip: 0.0.0.0
      listen-port: 6000
  loggers:
  - name: loki
    lokiclient:
      server-url: "https://grafana-loki.example.com/loki/api/v1/push"
      job-name: "dnscollector"
      mode: "flat-json"
      tls-insecure: true
      tenant-id: fake
      relabel-configs:
      - source_labels: ["__dns_qtype"]
        target_label: "qtype"
        replacement: "test"
        action: "update"
        separator: ","
        regex: "test"
  routes:
  - from: [ tap ]
    to: [ loki ]
`,
			wantErr: false,
		},
		{
			name: "freeform scalyr #676",
			content: `
multiplexer:
  collectors:
  - name: tap
    dnstap:
      listen-ip: 0.0.0.0
      listen-port: 6000
  loggers:
  - name: scalyr
    scalyrclient:
      apikey: XXXXX
      attrs:
        service: dnstap
        type: queries
      flush-interval: 10
      mode: flat-json
      sessioninfo:
        cloud_provider: Azure
        cloud_region: westeurope
  routes:
  - from: [ tap ]
    to: [ scalyr ]
`,
			wantErr: false,
		},
		{
			name: "Valid tranforms key with flow argument",
			content: `
multiplexer:
  collectors:
  - name: tap
    dnstap:
      listen-ip: 0.0.0.0
    transforms:
      atags:
        tags: [ "TXT:google", "MX:apple" ]
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, err := createTempConfigFile(tt.content)
			if err != nil {
				t.Fatalf("Error creating temporary file: %v", err)
			}
			defer os.Remove(tempFile)
			configFile, err := os.Open(tempFile)
			if err != nil {
				t.Fatalf("Read temporary file: %v", err)
			}
			defer configFile.Close()

			err = CheckConfig(configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
