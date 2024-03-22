package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

var (
	TestIP4 = "192.168.1.2"
	TestIP6 = "fe80::6111:626:c1b2:2353"
)

// bench
func BenchmarkUserPrivacy_ReduceQname(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.MinimazeQname = true

	log := logger.New(false)
	channels := []chan dnsutils.DNSMessage{}

	subprocessor := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, channels, log.Info, log.Error)
	qname := "localhost.domain.local.home"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.MinimazeQname(qname)
	}
}

func BenchmarkUserPrivacy_HashIP(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashIP = true

	log := logger.New(false)
	channels := []chan dnsutils.DNSMessage{}

	subprocessor := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, channels, log.Info, log.Error)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.HashIP(TestIP4)
	}
}

func BenchmarkUserPrivacy_HashIPSha512(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashIP = true
	config.UserPrivacy.HashIPAlgo = "sha512"

	log := logger.New(false)
	channels := []chan dnsutils.DNSMessage{}

	subprocessor := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, channels, log.Info, log.Error)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.HashIP(TestIP4)
	}
}

func BenchmarkUserPrivacy_AnonymizeIP(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	log := logger.New(false)
	channels := []chan dnsutils.DNSMessage{}

	subprocessor := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, channels, log.Info, log.Error)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.AnonymizeIP(TestIP4)
	}
}

// other tests
func TestUserPrivacy_ReduceQname(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
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

func TestUserPrivacy_HashIPDefault(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashIP = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	ret := userPrivacy.HashIP(TestIP4)
	if ret != "c0ca1efec6aaf505e943397662c28f89ac8f3bc2" {
		t.Errorf("IP hashing failed, got %s", ret)
	}
}

func TestUserPrivacy_HashIPSha512(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashIP = true
	config.UserPrivacy.HashIPAlgo = "sha512"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	ret := userPrivacy.HashIP(TestIP4)
	if ret != "800e8f97a29404b7031dfb8d7185b2d30a3cd326b535cda3dcec20a0f4749b1099f98e49245d67eb188091adfba9a45dc0c15e612b554ae7181d8f8a479b67a0" {
		t.Errorf("IP hashing failed, got %s", ret)
	}
}

func TestUserPrivacy_AnonymizeIPv4DefaultMask(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	ret := userPrivacy.AnonymizeIP(TestIP4)
	if ret != "192.168.0.0" {
		t.Errorf("Ipv4 anonymization failed, got %s", ret)
	}
}

func TestUserPrivacy_AnonymizeIPv6DefaultMask(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	ret := userPrivacy.AnonymizeIP(TestIP6)
	if ret != "fe80::" {
		t.Errorf("Ipv6 anonymization failed, got %s", ret)
	}
}

func TestUserPrivacy_AnonymizeIPv4RemoveIP(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true
	config.UserPrivacy.AnonymizeIPV4Bits = "/0"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	ret := userPrivacy.AnonymizeIP(TestIP4)
	if ret != "0.0.0.0" {
		t.Errorf("Ipv4 anonymization failed with mask %s, got %s", config.UserPrivacy.AnonymizeIPV4Bits, ret)
	}
}

func TestUserPrivacy_AnonymizeIPv6RemoveIP(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true
	config.UserPrivacy.AnonymizeIPV6Bits = "::/0"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacySubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	ret := userPrivacy.AnonymizeIP(TestIP6)
	if ret != "::" {
		t.Errorf("Ipv6 anonymization failed, got %s", ret)
	}
}
