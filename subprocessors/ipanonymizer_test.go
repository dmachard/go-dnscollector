package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestAnonymizeIPv4(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.UserPrivacy.AnonymizeIP = true

	// init the processor
	anonIp := NewIpAnonymizerSubprocessor(config)

	ip := "192.168.1.2"
	if !anonIp.IsEnabled() {
		t.Errorf("feature not enabled")
	}

	ret := anonIp.Anonymize(ip)
	if ret != "192.168.0.0" {
		t.Errorf("Ipv4 anonymization failed, got %s", ret)
	}
}

func TestAnonymizeIPv6(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.UserPrivacy.AnonymizeIP = true

	// init the processor
	anonIp := NewIpAnonymizerSubprocessor(config)

	ip := "fe80::6111:626:c1b2:2353"
	if !anonIp.IsEnabled() {
		t.Errorf("feature not enabled")
	}

	ret := anonIp.Anonymize(ip)
	if ret != "fe80::" {
		t.Errorf("Ipv6 anonymization failed, got %s", ret)
	}
}
