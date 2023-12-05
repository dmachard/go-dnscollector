package pkgconfig

import "testing"

func TestConfigLoggersSetDefault(t *testing.T) {
	config := ConfigLoggers{}
	config.SetDefault()

	if config.Stdout.Enable != false {
		t.Errorf("stdout should be disabled")
	}
	if config.DNSTap.Enable != false {
		t.Errorf("dnstap should be disabled")
	}
	if config.LogFile.Enable != false {
		t.Errorf("log file should be disabled")
	}
	if config.Prometheus.Enable != false {
		t.Errorf("prometheus should be disabled")
	}
}
