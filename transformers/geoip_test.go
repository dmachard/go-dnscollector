package transformers

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/stretchr/testify/require"
)

func TestGeoIP_Json(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	outChans := []chan dnsutils.DNSMessage{}

	// get fake
	dm := dnsutils.GetFakeDNSMessage()
	dm.Init()

	// init subproccesor
	geoip := NewDNSGeoIPTransform(config, logger.New(true), "test", 0, outChans)
	if err := geoip.Open(); err != nil {
		t.Fatalf("geoip init failed: %v+", err)
	}
	defer geoip.Close()

	geoip.GetTransforms()
	geoip.geoipTransform(&dm)

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
	config.GeoIP.Enable = true
	config.GeoIP.DBCountryFile = "../tests/testsdata/GeoLite2-Country.mmdb"

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	geoip := NewDNSGeoIPTransform(config, logger.New(false), "test", 0, outChans)
	_, err := geoip.GetTransforms()
	if err != nil {
		t.Fatalf("geoip init failed: %v+", err)
	}
	defer geoip.Close()

	// create test message
	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "83.112.146.176"

	// apply subprocessors
	returnCode, err := geoip.geoipTransform(&dm)
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

func TestGeoIP_LookupAsn(t *testing.T) {
	// enable geoip
	config := pkgconfig.GetFakeConfigTransformers()
	config.GeoIP.Enable = true
	config.GeoIP.DBASNFile = "../tests/testsdata/GeoLite2-ASN.mmdb"

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	geoip := NewDNSGeoIPTransform(config, logger.New(false), "test", 0, outChans)
	if err := geoip.Open(); err != nil {
		t.Fatalf("geoip init failed: %v", err)
	}
	defer geoip.Close()

	// lookup
	geoInfo, err := geoip.Lookup("83.112.146.176")
	if err != nil {
		t.Errorf("geoip loopkup failed: %v", err)
	}

	if geoInfo.ASO != "Orange" {
		t.Errorf("asn organisation invalid want: XX got: %s", geoInfo.ASO)
	}
}

func TestGeoIP_Lookup_ECS(t *testing.T) {
	// enable geoip
	config := pkgconfig.GetFakeConfigTransformers()
	config.GeoIP.Enable = true
	config.GeoIP.DBCountryFile = "../tests/testsdata/GeoLite2-Country.mmdb"
	config.GeoIP.LookupECS = true

	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	geoip := NewDNSGeoIPTransform(config, logger.New(false), "test", 0, outChans)
	_, err := geoip.GetTransforms()
	if err != nil {
		t.Fatalf("geoip init failed: %v+", err)
	}
	defer geoip.Close()

	// Create a test DNS message with EDNS ECS data
	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "1.1.1.1"                                                                            // AU
	dm.EDNS.Options = append(dm.EDNS.Options, dnsutils.DNSOption{Code: 8, Name: "CSUBNET", Data: "1.58.30.6/32"}) // CN

	// Apply the transform
	returnCode, err := geoip.geoipTransform(&dm)
	require.NoError(t, err, "process transform failed")

	// Validate the country code
	require.Equal(t, "CN", dm.Geo.CountryIsoCode, "country code mismatch")

	// Ensure the return code is ReturnKeep
	require.Equal(t, ReturnKeep, returnCode, "unexpected return code")
}
