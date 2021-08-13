package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnslogger/dnsutils"
)

func TestGeoIP(t *testing.T) {
	// enable geoip
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.GeoIP.DbFile = "../testsdata/GeoLite2-Country.mmdb"

	// init the processor
	geoip := NewDnsGeoIpProcessor(config)
	if err := geoip.Open(); err != nil {
		t.Errorf("geoip init failed: %v+", err)
	}
	defer geoip.Close()

	// feature is enabled ?
	if !geoip.IsEnabled() {
		t.Errorf("geoip should be enabled")
	}

	// lookup
	country, err := geoip.Lookup("92.184.1.1")
	if err != nil {
		t.Errorf("geoip loopkup failed: %v+", err)
	}

	if country != "FR" {
		t.Errorf("country invalid want: XX got: %s", country)
	}
}
