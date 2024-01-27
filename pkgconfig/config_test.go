package pkgconfig

import (
	"os"
	"testing"

	"github.com/pkg/errors"
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

// Valid minimal user configuration
func TestConfig_CheckConfig_Valid(t *testing.T) {
	// Create a temporary file for the user configuration
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	validUserConfigContent := `
global:
  trace: false
multiplexer:
  routes:
    - from: [test-route]
  loggers:
    - name: test-logger
  collectors:
    - name: test-collector
`
	err = os.WriteFile(userConfigFile.Name(), []byte(validUserConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	if err := CheckConfig(userConfigFile.Name(), dm); err != nil {
		t.Errorf("failed: Unexpected error: %v", err)
	}
}

// Invalid user configuration with an unknown key
func TestConfig_CheckConfig_UnknownKeywords(t *testing.T) {
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	userConfigContent := `
global:
  trace: false
multiplexer:
  routes:
  - from: [test-route]
    unknown-key: invalid
`
	err = os.WriteFile(userConfigFile.Name(), []byte(userConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	expectedError := errors.Errorf("unknown YAML key `unknown-key` in configuration")
	if err := CheckConfig(userConfigFile.Name(), dm); err == nil || err.Error() != expectedError.Error() {
		t.Errorf("Expected error %v, but got %v", expectedError, err)
	}
}

// Ignore dynamic keys
func TestConfig_CheckConfig_IgnoreDynamicKeys(t *testing.T) {
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	userConfigContent := `
global:
  trace: false
pipelines:
  - name: match
    dnsmessage:
      matching:
        include:
          atags.tags.*: test
          atags.tags.2: test
          dns.resources-records.*: test
          dns.resources-records.10.rdata: test
          dns.resources-records.*.ttl: test
`
	err = os.WriteFile(userConfigFile.Name(), []byte(userConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	if err := CheckConfig(userConfigFile.Name(), dm); err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
}

// Keywork exist but not at the good position
func TestConfig_CheckConfig_BadKeywordPosition(t *testing.T) {
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	userConfigContent := `
global:
  trace: false
  logger: bad-position
`
	err = os.WriteFile(userConfigFile.Name(), []byte(userConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	if err := CheckConfig(userConfigFile.Name(), dm); err == nil {
		t.Errorf("Expected error, but got %v", err)
	}
}

// Valid multiplexer configuration
func TestConfig_CheckMultiplexerConfig_Valid(t *testing.T) {
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	userConfigContent := `
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
`
	err = os.WriteFile(userConfigFile.Name(), []byte(userConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	if err := CheckConfig(userConfigFile.Name(), dm); err != nil {
		t.Errorf("failed: Unexpected error: %v", err)
	}
}

// Invalid multiplexer configuration
func TestConfig_CheckMultiplexerConfig_Invalid(t *testing.T) {
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	userConfigContent := `
global:
  trace: false
multiplexer:
- name: block
  dnstap:
    listen-ip: 0.0.0.0
	transforms:
      normalize:
        qname-lowercase: true
`

	err = os.WriteFile(userConfigFile.Name(), []byte(userConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	if err := CheckConfig(userConfigFile.Name(), dm); err == nil {
		t.Errorf("Expected error, but got %v", err)
	}
}

// https://github.com/dmachard/go-dnscollector/issues/565
func TestConfig_CheckMultiplexerConfig_InvalidLogger(t *testing.T) {
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	// all keywords in this config are valid but the logger dnstap is not valid in this context
	userConfigContent := `
global:
  trace: false
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
`

	err = os.WriteFile(userConfigFile.Name(), []byte(userConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	if err := CheckConfig(userConfigFile.Name(), dm); err == nil {
		t.Errorf("Expected error, but got %v", err)
	}
}

// Valid pipeline configuration
func TestConfig_CheckPipelinesConfig_Valid(t *testing.T) {
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	userConfigContent := `
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
`
	err = os.WriteFile(userConfigFile.Name(), []byte(userConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	if err := CheckConfig(userConfigFile.Name(), dm); err != nil {
		t.Errorf("failed: Unexpected error: %v", err)
	}
}

// Invalid pipeline configuration
func TestConfig_CheckPipelinesConfig_Invalid(t *testing.T) {
	userConfigFile, err := os.CreateTemp("", "user-config.yaml")
	if err != nil {
		t.Fatal("Error creating temporary file:", err)
	}
	defer os.Remove(userConfigFile.Name())
	defer userConfigFile.Close()

	userConfigContent := `
pipelines:
- name: dnsdist-main
  dnstap:
    listen-ip: 0.0.0.0
    transforms:
      normalize:
        qname-lowercase: true
  routing-policy: 
    default: [ console ]
`

	err = os.WriteFile(userConfigFile.Name(), []byte(userConfigContent), 0644)
	if err != nil {
		t.Fatal("Error writing to user configuration file:", err)
	}

	dm := make(map[string]interface{})
	if err := CheckConfig(userConfigFile.Name(), dm); err == nil {
		t.Errorf("Expected error, but got %v", err)
	}
}
