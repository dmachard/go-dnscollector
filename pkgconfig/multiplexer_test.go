package pkgconfig

import "testing"

func TestConfigMultiplexerSetDefault(t *testing.T) {
	config := ConfigMultiplexer{}
	config.SetDefault()

	// Check that the slices are initialized to empty slices
	if len(config.Collectors) != 0 {
		t.Errorf("Expected Collectors to be an empty slice, got %v", config.Collectors)
	}

	if len(config.Loggers) != 0 {
		t.Errorf("Expected Loggers to be an empty slice, got %v", config.Loggers)
	}

	if len(config.Routes) != 0 {
		t.Errorf("Expected Routes to be an empty slice, got %v", config.Routes)
	}
}
