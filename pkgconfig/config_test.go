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
