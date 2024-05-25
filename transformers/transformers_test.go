package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

const (
	IPv6Address = "fe80::6111:626:c1b2:2353"
	CapsAddress = "www.Google.Com"
	NormAddress = "www.google.com"
	IPv6ShortND = "fe80::"
	Localhost   = "localhost"
)

// Bench to init DNS message
func BenchmarkTransforms_InitAndProcess(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true
	config.GeoIP.Enable = true
	config.GeoIP.DBCountryFile = ".././tests/testsdata/GeoLite2-Country.mmdb"
	config.GeoIP.DBASNFile = ".././tests/testsdata/GeoLite2-ASN.mmdb"
	config.UserPrivacy.Enable = true
	config.UserPrivacy.MinimazeQname = true
	config.UserPrivacy.AnonymizeIP = true
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = ".././tests/testsdata/filtering_keep_domains.txt"

	channels := []chan dnsutils.DNSMessage{}
	transformers := NewTransforms(config, logger.New(false), "test", channels, 0)

	dm := dnsutils.GetFakeDNSMessage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transformers.ProcessMessage(&dm)
	}
}

// Other tests
func TestTransformsSuspicious(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true

	// init subproccesor
	channels := []chan dnsutils.DNSMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels, 0)

	// malformed DNS message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.MalformedPacket = true

	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err: %v", err)
	}

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 1.0")
	}

	if dm.Suspicious.MalformedPacket != true {
		t.Errorf("suspicious malformed packet flag should be equal to true")
	}

	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
}

func TestTransformsGeoIPLookupCountry(t *testing.T) {
	// enable geoip
	config := pkgconfig.GetFakeConfigTransformers()
	config.GeoIP.Enable = true
	config.GeoIP.DBCountryFile = "../tests/testsdata/GeoLite2-Country.mmdb"

	// init processor
	channels := []chan dnsutils.DNSMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "83.112.146.176"

	// apply subprocessors
	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err: %v", err)
	}

	if dm.Geo.CountryIsoCode != "FR" {
		t.Errorf("country invalid want: FR got: %s", dm.Geo.CountryIsoCode)
	}

	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
}

func TestTransformsGeoIPLookupAsn(t *testing.T) {
	// enable geoip
	config := pkgconfig.GetFakeConfigTransformers()
	config.GeoIP.Enable = true
	config.GeoIP.DBASNFile = "../tests/testsdata/GeoLite2-ASN.mmdb"

	// init the processor
	channels := []chan dnsutils.DNSMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "83.112.146.176"

	// apply subprocessors
	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err: %v", err)
	}

	if dm.Geo.AutonomousSystemOrg != "Orange" {
		t.Errorf("asn organisation invalid want: Orange got: %s", dm.Geo.AutonomousSystemOrg)
	}

	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
}

func TestTransformsAnonymizeIPv4(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	// init the processor
	channels := []chan dnsutils.DNSMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "192.168.1.2"

	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if dm.NetworkInfo.QueryIP != "192.168.0.0" {
		t.Errorf("Ipv4 anonymization failed, got %v", dm.NetworkInfo.QueryIP)
	}
	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
}

func TestTransformsAnonymizeIPv6(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	// init the processor
	channels := []chan dnsutils.DNSMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()

	// init dns message with additional part
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if dm.NetworkInfo.QueryIP != IPv6ShortND {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIP)
	}
	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
}

func TestTransformsNormalizeLowercaseQname(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true

	// init the processor
	channels := []chan dnsutils.DNSMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = CapsAddress
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if dm.DNS.Qname != NormAddress {
		t.Errorf("Qname to lowercase failed, got %s", dm.DNS.Qname)
	}
	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
}

func TestMultiTransforms(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	// init the processor
	channels := []chan dnsutils.DNSMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = CapsAddress
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if dm.DNS.Qname != NormAddress {
		t.Errorf("Qname to lowercase failed, got %s", dm.DNS.Qname)
	}
	if dm.NetworkInfo.QueryIP != IPv6ShortND {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIP)
	}
	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
}

func TestTransformAndFilter(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	// file contains google.fr, test.github.com
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = "../tests/testsdata/filtering_keep_domains.txt"

	testURL1 := "mail.google.com"
	testURL2 := "test.github.com"

	// init the processor
	channels := []chan dnsutils.DNSMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()

	// should be dropped and not transformed
	dm.DNS.Qname = testURL1
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if returnCode != ReturnDrop {
		t.Errorf("Return code is %v and not RETURN_DROP (%v)", returnCode, ReturnDrop)
	}
	if dm.NetworkInfo.QueryIP == IPv6ShortND {
		t.Errorf("Ipv6 anonymization occurred (it should have dropped before filter)")
	}

	// should not be dropped, and should be transformed
	dm.DNS.Qname = testURL2
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err = subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
	if dm.NetworkInfo.QueryIP != IPv6ShortND {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIP)
	}
}
