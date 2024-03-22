package transformers

import (
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

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

func TestNormalize_SuffixUnmanaged(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	log := logger.New(true)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	psl := NewNormalizeSubprocessor(config, logger.New(true), "test", 0, outChans, log.Info, log.Error)

	dm := dnsutils.GetFakeDNSMessage()
	// https://publicsuffix.org/list/effective_tld_names.dat
	// // ===BEGIN ICANN DOMAINS===
	// ....
	// // ===END ICANN DOMAINS===
	// ===BEGIN PRIVATE DOMAINS===
	// ..
	dm.DNS.Qname = "play.googleapis.com"
	// // ===END PRIVATE DOMAINS===

	psl.InitDNSMessage(&dm)
	psl.GetEffectiveTld(&dm)
	if dm.PublicSuffix.ManagedByICANN {
		t.Errorf("Qname %s should be private domains", dm.DNS.Qname)
	}
}

func TestNormalize_SuffixICANNManaged(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	log := logger.New(true)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	psl := NewNormalizeSubprocessor(config, logger.New(true), "test", 0, outChans, log.Info, log.Error)

	dm := dnsutils.GetFakeDNSMessage()
	// https://publicsuffix.org/list/effective_tld_names.dat
	// // ===BEGIN ICANN DOMAINS===
	dm.DNS.Qname = "fr.wikipedia.org"
	// // ===END ICANN DOMAINS===
	// ===BEGIN PRIVATE DOMAINS===
	// ..
	// // ===END PRIVATE DOMAINS===

	psl.InitDNSMessage(&dm)
	psl.GetEffectiveTld(&dm)
	if !dm.PublicSuffix.ManagedByICANN {
		t.Errorf("Qname %s should be ICANN managed", dm.DNS.Qname)
	}
}

// bench tests

func BenchmarkNormalize_GetEffectiveTld(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()

	log := logger.New(false)
	channels := []chan dnsutils.DNSMessage{}

	subprocessor := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, channels, log.Info, log.Error)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "en.wikipedia.org"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.InitDNSMessage(&dm)
		subprocessor.GetEffectiveTld(&dm)
	}
}

func BenchmarkNormalize_GetEffectiveTldPlusOne(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()

	log := logger.New(false)
	channels := []chan dnsutils.DNSMessage{}

	subprocessor := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, channels, log.Info, log.Error)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "en.wikipedia.org"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.InitDNSMessage(&dm)
		subprocessor.GetEffectiveTld(&dm)
	}
}

func BenchmarkNormalize_QnameLowercase(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()

	log := logger.New(false)
	channels := []chan dnsutils.DNSMessage{}

	subprocessor := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, channels, log.Info, log.Error)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "EN.Wikipedia.Org"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.LowercaseQname(&dm)
	}
}

func BenchmarkNormalize_QuietText(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()

	log := logger.New(false)
	channels := []chan dnsutils.DNSMessage{}

	subprocessor := NewNormalizeSubprocessor(config, logger.New(false), "test", 0, channels, log.Info, log.Error)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "EN.Wikipedia.Org"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.QuietText(&dm)
	}
}
