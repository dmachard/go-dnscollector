package config

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
	if config.KafkaProducer.Partition != nil {
		t.Errorf("kafka partition should be nil by default")
	}
	if config.FalcoClient.URL != "http://127.0.0.1:9200" {
		t.Errorf("falco URL should have its default value, got %q", config.FalcoClient.URL)
	}
}
