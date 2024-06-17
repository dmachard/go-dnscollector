package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

const (
	IPv6Address = "fe80::6111:626:c1b2:2353"
	CapsAddress = "www.Google.Com"
	NormAddress = "www.google.com"

	Localhost = "localhost"
)

// Bench to init DNS message
func BenchmarkTransforms_InitAndProcess(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true
	config.GeoIP.Enable = true
	config.GeoIP.DBCountryFile = ".././tests/testsdata/GeoLite2-Country.mmdb"
	config.GeoIP.DBASNFile = ".././tests/testsdata/GeoLite2-ASN.mmdb"
	config.UserPrivacy.Enable = true
	config.UserPrivacy.MinimazeQname = true
	config.UserPrivacy.AnonymizeIP = true
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = ".././tests/testsdata/filtering_keep_domains.txt"

	channels := []chan dnsutils.DNSMessage{}
	transformers := NewTransforms(config, logger.New(false), "test", channels, 0)

	dm := dnsutils.GetFakeDNSMessage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transformers.ProcessMessage(&dm)
	}
}

func TestTransforms_ProcessOrder(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = "../tests/testsdata/filtering_keep_domains.txt" // file contains google.fr, test.github.com

	testURL1 := "mail.google.com"
	testURL2 := "test.github.com"

	// init the transformer
	subprocessors := NewTransforms(config, logger.New(false), "test", []chan dnsutils.DNSMessage{}, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()

	// should be dropped and not transformed
	dm.DNS.Qname = testURL1
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if returnCode != ReturnDrop {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}

	// should not be dropped, and should be transformed
	dm.DNS.Qname = testURL2
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err = subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
	if dm.NetworkInfo.QueryIP != IPv6ShortND {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIP)
	}
}
