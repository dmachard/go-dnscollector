package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestReduceQname(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.MinimazeQname = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	qname := "www.google.com"
	ret := userPrivacy.MinimazeQname(qname)
	if ret != "google.com" {
		t.Errorf("Qname minimization failed, got %s", ret)
	}

	qname = "localhost"
	ret = userPrivacy.MinimazeQname(qname)
	if ret != "localhost" {
		t.Errorf("Qname minimization failed, got %s", ret)
	}

	qname = "localhost.domain.local.home"
	ret = userPrivacy.MinimazeQname(qname)
	if ret != "local.home" {
		t.Errorf("Qname minimization failed, got %s", ret)
	}
}

func TestAnonymizeIPv4(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	ip := "192.168.1.2"

	ret := userPrivacy.AnonymizeIP(ip)
	if ret != "192.168.0.0" {
		t.Errorf("Ipv4 anonymization failed, got %s", ret)
	}
}

func TestAnonymizeIPv6(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	ip := "fe80::6111:626:c1b2:2353"

	ret := userPrivacy.AnonymizeIP(ip)
	if ret != "fe80::" {
		t.Errorf("Ipv6 anonymization failed, got %s", ret)
	}
}
