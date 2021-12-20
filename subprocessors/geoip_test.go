package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestGeoIP_LookupCountry(t *testing.T) {
	// enable geoip
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.GeoIP.DbCountryFile = "../testsdata/GeoLite2-Country.mmdb"

	// init the processor
	geoip := NewDnsGeoIpProcessor(config, logger.New(false))
	if err := geoip.Open(); err != nil {
		t.Fatalf("geoip init failed: %v+", err)
	}
	defer geoip.Close()

	// feature is enabled ?
	if !geoip.IsEnabled() {
		t.Fatalf("geoip should be enabled")
	}

	// lookup
	geoInfo, err := geoip.Lookup("92.184.1.1")
	if err != nil {
		t.Errorf("geoip loopkup failed: %v+", err)
	}

	if geoInfo.CountryISOCode != "FR" {
		t.Errorf("country invalid want: XX got: %s", geoInfo.CountryISOCode)
	}
}

func TestGeoIP_LookupAsn(t *testing.T) {
	// enable geoip
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.GeoIP.DbAsnFile = "../testsdata/GeoLite2-ASN.mmdb"

	// init the processor
	geoip := NewDnsGeoIpProcessor(config, logger.New(false))
	if err := geoip.Open(); err != nil {
		t.Fatalf("geoip init failed: %v", err)
	}
	defer geoip.Close()

	// feature is enabled ?
	if !geoip.IsEnabled() {
		t.Fatalf("geoip should be enabled")
	}

	// lookup
	geoInfo, err := geoip.Lookup("83.112.146.176")
	if err != nil {
		t.Errorf("geoip loopkup failed: %v", err)
	}
	if geoInfo.ASO != "Orange" {
		t.Errorf("asn organisation invalid want: XX got: %s", geoInfo.ASO)
	}
}
