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

	channels := []chan dnsutils.DNSMessage{}

	userprivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, channels)
	userprivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "localhost.domain.local.home"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userprivacy.minimazeQname(&dm)
	}
}

func BenchmarkUserPrivacy_HashIP(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashQueryIP = true

	channels := []chan dnsutils.DNSMessage{}

	userprivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, channels)
	userprivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userprivacy.hashQueryIP(&dm)
	}
}

func BenchmarkUserPrivacy_HashIPSha512(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashQueryIP = true
	config.UserPrivacy.HashIPAlgo = "sha512"

	channels := []chan dnsutils.DNSMessage{}

	userprivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, channels)
	userprivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userprivacy.hashQueryIP(&dm)
	}
}

func BenchmarkUserPrivacy_AnonymizeIP(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	channels := []chan dnsutils.DNSMessage{}

	userprivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, channels)
	userprivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userprivacy.anonymizeQueryIP(&dm)
	}
}

// other tests
func TestUserPrivacy_ReduceQname(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.MinimazeQname = true

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "www.google.com"

	userPrivacy.minimazeQname(&dm)
	if dm.DNS.Qname != "google.com" {
		t.Errorf("Qname minimization failed, got %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "localhost"
	userPrivacy.minimazeQname(&dm)
	if dm.DNS.Qname != "localhost" {
		t.Errorf("Qname minimization failed, got %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "localhost.domain.local.home"
	userPrivacy.minimazeQname(&dm)
	if dm.DNS.Qname != "local.home" {
		t.Errorf("Qname minimization failed, got %s", dm.DNS.Qname)
	}
}

func TestUserPrivacy_HashIPDefault(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashQueryIP = true

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = TestIP4

	userPrivacy.hashQueryIP(&dm)
	if dm.NetworkInfo.QueryIP != "c0ca1efec6aaf505e943397662c28f89ac8f3bc2" {
		t.Errorf("IP hashing failed, got %s", dm.NetworkInfo.QueryIP)
	}
}

func TestUserPrivacy_HashIPSha512(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashQueryIP = true
	config.UserPrivacy.HashIPAlgo = "sha512"

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = TestIP4

	userPrivacy.hashQueryIP(&dm)
	if dm.NetworkInfo.QueryIP != "800e8f97a29404b7031dfb8d7185b2d30a3cd326b535cda3dcec20a0f4749b1099f98e49245d67eb188091adfba9a45dc0c15e612b554ae7181d8f8a479b67a0" {
		t.Errorf("IP hashing failed, got %s", dm.NetworkInfo.QueryIP)
	}
}

func TestUserPrivacy_AnonymizeIPv4DefaultMask(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = TestIP4

	userPrivacy.anonymizeQueryIP(&dm)
	if dm.NetworkInfo.QueryIP != "192.168.0.0" {
		t.Errorf("Ipv4 anonymization failed, got %s", dm.NetworkInfo.QueryIP)
	}
}

func TestUserPrivacy_AnonymizeIPv6DefaultMask(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = TestIP6

	userPrivacy.anonymizeQueryIP(&dm)
	if dm.NetworkInfo.QueryIP != "fe80::" {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIP)
	}
}

func TestUserPrivacy_AnonymizeIPv4RemoveIP(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true
	config.UserPrivacy.AnonymizeIPV4Bits = "/0"

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = TestIP4

	userPrivacy.anonymizeQueryIP(&dm)
	if dm.NetworkInfo.QueryIP != "0.0.0.0" {
		t.Errorf("Ipv4 anonymization failed with mask %s, got %s", config.UserPrivacy.AnonymizeIPV4Bits, dm.NetworkInfo.QueryIP)
	}
}

func TestUserPrivacy_AnonymizeIPv6RemoveIP(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true
	config.UserPrivacy.AnonymizeIPV6Bits = "::/0"

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	userPrivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = TestIP6

	userPrivacy.anonymizeQueryIP(&dm)
	if dm.NetworkInfo.QueryIP != "::" {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIP)
	}
}
