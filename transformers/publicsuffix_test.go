package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestPublicSuffixAddTLD(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.PublicSuffix.Enable = true
	config.PublicSuffix.AddTld = true

	// init the processor
	psl := NewPublicSuffixSubprocessor(config)

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

func TestPublicSuffixAddTldPlusOne(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.PublicSuffix.Enable = true
	config.PublicSuffix.AddTld = true

	// init the processor
	psl := NewPublicSuffixSubprocessor(config)

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
