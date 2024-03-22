package pkgconfig

import "testing"

func TestConfigGlobalSetDefault(t *testing.T) {
	// Create a ConfigGlobal instance
	config := ConfigGlobal{}

	// Call SetDefault to set default values
	config.SetDefault()

	if config.Trace.Verbose != false {
		t.Errorf("verbose mode should be disabled")
	}
}
