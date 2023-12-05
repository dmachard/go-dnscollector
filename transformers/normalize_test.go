package transformers

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestNormalize_Json(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// get fake
	dm := dnsutils.GetFakeDNSMessage()
	dm.Init()

	// init subproccesor
	qnameNorm := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	qnameNorm.InitDNSMessage(&dm)

	// expected json
	refJSON := `
			{
				"publicsuffix": {
					"tld":"-",
					"etld+1":"-"
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

	if _, ok := dmMap["publicsuffix"]; !ok {
		t.Fatalf("transformer key is missing")
	}

	if !reflect.DeepEqual(dmMap["publicsuffix"], refMap["publicsuffix"]) {
		t.Errorf("json format different from reference")
	}
}

func TestNormalize_LowercaseQname(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	qnameNorm := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	qname := "www.Google.Com"
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = qname

	ret := qnameNorm.LowercaseQname(&dm)
	if dm.DNS.Qname != strings.ToLower(qname) {
		t.Errorf("Qname to lowercase failed, got %d", ret)
	}
}

func TestNormalize_QuietText(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QuietText = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	norm := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	dm := dnsutils.GetFakeDNSMessage()
	norm.QuietText(&dm)

	if dm.DNSTap.Operation != "CQ" {
		t.Errorf("CQ expected: %s", dm.DNSTap.Operation)
	}

	if dm.DNS.Type != "Q" {
		t.Errorf("Q expected: %s", dm.DNS.Type)
	}
}

func TestNormalize_AddTLD(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.AddTld = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	psl := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	tt := []struct {
		name  string
		qname string
		want  string
	}{
		{
			name:  "get tld",
			qname: "www.amazon.fr",
			want:  "fr",
		},
		{
			name:  "get tld insensitive",
			qname: "www.Google.Com",
			want:  "com",
		},
		{
			name:  "get tld with dot trailing",
			qname: "www.amazon.fr.",
			want:  "fr",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			dm := dnsutils.GetFakeDNSMessage()
			dm.DNS.Qname = tc.qname

			psl.InitDNSMessage(&dm)

			psl.GetEffectiveTld(&dm)
			if dm.PublicSuffix.QnamePublicSuffix != tc.want {
				t.Errorf("Bad TLD, got: %s, expected: com", dm.PublicSuffix.QnamePublicSuffix)

			}
		})
	}
}

func TestNormalize_AddTldPlusOne(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.AddTld = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	psl := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	tt := []struct {
		name  string
		qname string
		want  string
	}{
		{
			name:  "get tld",
			qname: "www.amazon.fr",
			want:  "amazon.fr",
		},
		{
			name:  "get tld insensitive",
			qname: "books.amazon.co.uk",
			want:  "amazon.co.uk",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			dm := dnsutils.GetFakeDNSMessage()
			dm.DNS.Qname = tc.qname

			psl.InitDNSMessage(&dm)

			psl.GetEffectiveTldPlusOne(&dm)
			if dm.PublicSuffix.QnameEffectiveTLDPlusOne != tc.want {
				t.Errorf("Bad TLD, got: %s, expected: %s", dm.PublicSuffix.QnameEffectiveTLDPlusOne, tc.want)

			}
		})
	}
}
