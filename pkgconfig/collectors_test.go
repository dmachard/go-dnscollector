package pkgconfig

import "testing"

func TestConfigCollectorsSetDefault(t *testing.T) {
	config := ConfigCollectors{}
	config.SetDefault()

	if config.Dnstap.Enable != false {
		t.Errorf("dnstap should be disabled")
	}
	if config.PowerDNS.Enable != false {
		t.Errorf("powerdns should be disabled")
	}
	if config.Tail.Enable != false {
		t.Errorf("tail should be disabled")
	}
	if config.AfpacketLiveCapture.Enable != false {
		t.Errorf("sniffer afpacket should be disabled")
	}
}
