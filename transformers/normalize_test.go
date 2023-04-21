package transformers

import (
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestNormalize_LowercaseQname(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true

	// init the processor
	qnameNorm := NewNormalizeSubprocessor(config, logger.New(false), "test")

	qname := "www.Google.Com"
	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = qname

	ret := qnameNorm.LowercaseQname(&dm)
	if dm.DNS.Qname != strings.ToLower(qname) {
		t.Errorf("Qname to lowercase failed, got %d", ret)
	}
}

func TestNormalize_QuietText(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QuietText = true

	// init the processor
	norm := NewNormalizeSubprocessor(config, logger.New(false), "test")

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
	psl := NewNormalizeSubprocessor(config, logger.New(false), "test")

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

			dm := dnsutils.GetFakeDnsMessage()
			dm.DNS.Qname = tc.qname

			psl.InitDnsMessage(&dm)

			psl.GetEffectiveTld(&dm)
			if dm.PublicSuffix.QnamePublicSuffix != tc.want {
				t.Errorf("Bad TLD, got: %s, expected: com", dm.PublicSuffix.QnamePublicSuffix)

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
	psl := NewNormalizeSubprocessor(config, logger.New(false), "test")

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

			dm := dnsutils.GetFakeDnsMessage()
			dm.DNS.Qname = tc.qname

			psl.InitDnsMessage(&dm)

			psl.GetEffectiveTldPlusOne(&dm)
			if dm.PublicSuffix.QnameEffectiveTLDPlusOne != tc.want {
				t.Errorf("Bad TLD, got: %s, expected: com", dm.PublicSuffix.QnameEffectiveTLDPlusOne)

			}
		})
	}
}
