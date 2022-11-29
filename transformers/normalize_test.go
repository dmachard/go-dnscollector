package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestNormalize_LowercaseQname(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true

	// init the processor
	qnameNorm := NewNormalizeSubprocessor(config)

	qname := "www.Google.Com"
	ret := qnameNorm.Lowercase(qname)
	if ret != "www.google.com" {
		t.Errorf("Qname to lowercase failed, got %s", ret)
	}
}

func TestNormalize_QuietText(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QuietText = true

	// init the processor
	norm := NewNormalizeSubprocessor(config)

	dm := dnsutils.GetFakeDnsMessage()
	norm.QuietText(&dm)

	if dm.DnsTap.Operation != "CQ" {
		t.Errorf("CQ expected: %s", dm.DnsTap.Operation)
	}

	if dm.DNS.Type != "Q" {
		t.Errorf("Q expected: %s", dm.DNS.Type)
	}
}

func TestNormalize_AddTLD(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.AddTld = true

	// init the processor
	psl := NewNormalizeSubprocessor(config)

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
			tld, err := psl.GetEffectiveTld(tc.qname)
			if err != nil {
				t.Errorf("Bad TLD with error: %s", err.Error())
			}
			if tld != tc.want {
				t.Errorf("Bad TLD, got: %s, expected: com", tld)

			}
		})
	}
}

func TestNormalize_AddTldPlusOne(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.AddTld = true

	// init the processor
	psl := NewNormalizeSubprocessor(config)

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
			tld, err := psl.GetEffectiveTldPlusOne(tc.qname)
			if err != nil {
				t.Errorf("Bad TLD with error: %s", err.Error())
			}
			if tld != tc.want {
				t.Errorf("Bad TLD, got: %s, expected: com", tld)

			}
		})
	}
}
