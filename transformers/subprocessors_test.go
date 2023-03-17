package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

const (
	IPV6_ADDRESS = "fe80::6111:626:c1b2:2353"
	CAPS_ADDRESS = "www.Google.Com"
	NORM_ADDRESS = "www.google.com"
	IPV6_SHORTND = "fe80::"
	LOCALHOST    = "localhost"
)

func TestTransformsSuspicious(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfigTransformers()
	config.Suspicious.Enable = true

	// init subproccesor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// malformed DNS message
	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.MalformedPacket = true

	// init dns message with additional part
	subprocessors.InitDnsMessageFormat(&dm)

	return_code := subprocessors.ProcessMessage(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 1.0")
	}

	if dm.Suspicious.MalformedPacket != true {
		t.Errorf("suspicious malformed packet flag should be equal to true")
	}

	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
}

func TestTransformsGeoIPLookupCountry(t *testing.T) {
	// enable geoip
	config := dnsutils.GetFakeConfigTransformers()
	config.GeoIP.Enable = true
	config.GeoIP.DbCountryFile = "../testsdata/GeoLite2-Country.mmdb"

	// init processor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// create test message
	dm := dnsutils.GetFakeDnsMessage()
	dm.NetworkInfo.QueryIp = "83.112.146.176"

	// init dns message with additional part
	subprocessors.InitDnsMessageFormat(&dm)

	// apply subprocessors
	return_code := subprocessors.ProcessMessage(&dm)

	if dm.Geo.CountryIsoCode != "FR" {
		t.Errorf("country invalid want: FR got: %s", dm.Geo.CountryIsoCode)
	}

	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
}

func TestTransformsGeoIPLookupAsn(t *testing.T) {
	// enable geoip
	config := dnsutils.GetFakeConfigTransformers()
	config.GeoIP.Enable = true
	config.GeoIP.DbAsnFile = "../testsdata/GeoLite2-ASN.mmdb"

	// init the processor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// create test message
	dm := dnsutils.GetFakeDnsMessage()
	dm.NetworkInfo.QueryIp = "83.112.146.176"

	// init dns message with additional part
	subprocessors.InitDnsMessageFormat(&dm)

	// apply subprocessors
	return_code := subprocessors.ProcessMessage(&dm)

	if dm.Geo.AutonomousSystemOrg != "Orange" {
		t.Errorf("asn organisation invalid want: Orange got: %s", dm.Geo.AutonomousSystemOrg)
	}

	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
}

func TestTransformsReduceQname(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.MinimazeQname = true

	// init the processor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// create test message
	dm := dnsutils.GetFakeDnsMessage()

	// init dns message with additional part
	subprocessors.InitDnsMessageFormat(&dm)

	// test 1: google.com
	dm.DNS.Qname = NORM_ADDRESS
	return_code := subprocessors.ProcessMessage(&dm)

	if dm.DNS.Qname != "google.com" {
		t.Errorf("Qname minimization failed, got %s", dm.DNS.Qname)
	}
	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}

	// test 2: localhost
	dm.DNS.Qname = LOCALHOST
	return_code = subprocessors.ProcessMessage(&dm)

	if dm.DNS.Qname != LOCALHOST {
		t.Errorf("Qname minimization failed, got %s", dm.DNS.Qname)
	}
	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}

	// test 3: local.home
	dm.DNS.Qname = "localhost.domain.local.home"
	return_code = subprocessors.ProcessMessage(&dm)

	if dm.DNS.Qname != "local.home" {
		t.Errorf("Qname minimization failed, got %s", dm.DNS.Qname)
	}
	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
}

func TestTransformsAnonymizeIPv4(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	// init the processor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// create test message
	dm := dnsutils.GetFakeDnsMessage()

	// init dns message with additional part
	subprocessors.InitDnsMessageFormat(&dm)

	dm.NetworkInfo.QueryIp = "192.168.1.2"

	return_code := subprocessors.ProcessMessage(&dm)
	if dm.NetworkInfo.QueryIp != "192.168.0.0" {
		t.Errorf("Ipv4 anonymization failed, got %v", dm.NetworkInfo.QueryIp)
	}
	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
}

func TestTransformsAnonymizeIPv6(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	// init the processor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// create test message
	dm := dnsutils.GetFakeDnsMessage()

	// init dns message with additional part
	subprocessors.InitDnsMessageFormat(&dm)

	dm.NetworkInfo.QueryIp = IPV6_ADDRESS

	return_code := subprocessors.ProcessMessage(&dm)
	if dm.NetworkInfo.QueryIp != IPV6_SHORTND {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIp)
	}
	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
}

func TestTransformsNormalizeLowercaseQname(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true

	// init the processor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// create test message
	dm := dnsutils.GetFakeDnsMessage()
	// init dns message with additional part
	subprocessors.InitDnsMessageFormat(&dm)

	dm.DNS.Qname = CAPS_ADDRESS
	dm.NetworkInfo.QueryIp = IPV6_ADDRESS

	return_code := subprocessors.ProcessMessage(&dm)
	if dm.DNS.Qname != NORM_ADDRESS {
		t.Errorf("Qname to lowercase failed, got %s", dm.DNS.Qname)
	}
	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
}

func TestMultiTransforms(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	// init the processor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// create test message
	dm := dnsutils.GetFakeDnsMessage()
	// init dns message with additional part
	subprocessors.InitDnsMessageFormat(&dm)

	dm.DNS.Qname = CAPS_ADDRESS
	dm.NetworkInfo.QueryIp = IPV6_ADDRESS

	return_code := subprocessors.ProcessMessage(&dm)
	if dm.DNS.Qname != NORM_ADDRESS {
		t.Errorf("Qname to lowercase failed, got %s", dm.DNS.Qname)
	}
	if dm.NetworkInfo.QueryIp != IPV6_SHORTND {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIp)
	}
	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
}

func TestTransformAndFilter(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	// file contains google.fr, test.github.com
	config.Filtering.KeepDomainFile = "../testsdata/filtering_keep_domains.txt"

	TEST_URL1 := "mail.google.com"
	TEST_URL2 := "test.github.com"

	// init the processor
	channels := []chan dnsutils.DnsMessage{}
	subprocessors := NewTransforms(config, logger.New(false), "test", channels)

	// create test message
	dm := dnsutils.GetFakeDnsMessage()

	// should be dropped and not transformed
	dm.DNS.Qname = TEST_URL1
	dm.NetworkInfo.QueryIp = IPV6_ADDRESS

	return_code := subprocessors.ProcessMessage(&dm)
	if return_code != RETURN_DROP {
		t.Errorf("Return code is %v and not RETURN_DROP (%v)", return_code, RETURN_DROP)
	}
	if dm.NetworkInfo.QueryIp == IPV6_SHORTND {
		t.Errorf("Ipv6 anonymization occurred (it should have dropped before filter)")
	}

	// should not be dropped, and should be transformed
	dm.DNS.Qname = TEST_URL2
	dm.NetworkInfo.QueryIp = IPV6_ADDRESS
	return_code = subprocessors.ProcessMessage(&dm)
	if return_code != RETURN_SUCCESS {
		t.Errorf("Return code is %v and not RETURN_SUCCESS (%v)", return_code, RETURN_SUCCESS)
	}
	if dm.NetworkInfo.QueryIp != IPV6_SHORTND {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIp)
	}
}
