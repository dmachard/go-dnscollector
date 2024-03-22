package transformers

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestGeoIP_Json(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// get fake
	dm := dnsutils.GetFakeDNSMessage()
	dm.Init()

	// init subproccesor
	geoip := NewDNSGeoIPProcessor(config, logger.New(true), "test", 0, outChans, log.Info, log.Error)
	if err := geoip.Open(); err != nil {
		t.Fatalf("geoip init failed: %v+", err)
	}
	defer geoip.Close()
	geoip.InitDNSMessage(&dm)

	// expected json
	refJSON := `
			{
				"geoip": {
					"city":"-",
					"continent":"-",
					"country-isocode":"-",
					"as-number":"-",
					"as-owner":"-"
				}
			}
			`

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJSON()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJSON), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if _, ok := dmMap["geoip"]; !ok {
		t.Fatalf("transformer key is missing")
	}

	if !reflect.DeepEqual(dmMap["geoip"], refMap["geoip"]) {
		t.Errorf("json format different from reference")
	}
}

func TestGeoIP_LookupCountry(t *testing.T) {
	// enable geoip
	config := pkgconfig.GetFakeConfigTransformers()
	config.GeoIP.DBCountryFile = "../testsdata/GeoLite2-Country.mmdb"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	geoip := NewDNSGeoIPProcessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
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
	config := pkgconfig.GetFakeConfigTransformers()
	config.GeoIP.DBASNFile = "../testsdata/GeoLite2-ASN.mmdb"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	geoip := NewDNSGeoIPProcessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
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
