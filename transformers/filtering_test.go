package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

const (
	testURL1 = "mail.google.com"
	testURL2 = "test.github.com"
)

func TestFilteringQR(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.LogQueries = false
	config.Filtering.LogReplies = false

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 2 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	if result, _ := filtering.dropQueryFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped")
	}

	dm.DNS.Type = dnsutils.DNSReply
	if result, _ := filtering.dropReplyFilter(&dm); result != ReturnDrop {
		t.Errorf("dns reply should be dropped")
	}
}

func TestFilteringByRcodeNOERROR(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropRcodes = []string{"NOERROR"}

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	if result, _ := filtering.dropRCodeFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped")
	}
}

func TestFilteringByRcodeEmpty(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropRcodes = []string{}

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 0 {
		t.Errorf("no subtransforms should be enabled")
	}
}

func TestFilteringByKeepQueryIp(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.KeepQueryIPFile = "../tests/testsdata/filtering_queryip_keep.txt"

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "192.168.0.1"
	if result, _ := filtering.keepQueryIPFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.168.1.10"
	if result, _ := filtering.keepQueryIPFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.3.2.1" // kept by subnet
	if result, _ := filtering.keepQueryIPFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByDropQueryIp(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropQueryIPFile = "../tests/testsdata/filtering_queryip.txt"

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "192.168.0.1"
	if result, _ := filtering.dropQueryIPFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.168.1.15"
	if result, _ := filtering.dropQueryIPFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.0.2.3" // dropped by subnet
	if result, _ := filtering.dropQueryIPFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

}

func TestFilteringByKeepRdataIp(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.KeepRdataFile = "../tests/testsdata/filtering_rdataip_keep.txt"

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.0.1",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.1.10",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.1.11", // included in subnet
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.0.2.3", // dropped by subnet
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.0.2.1",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2001:db8:85a3::8a2e:370:7334",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2041::7334",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2001:0dbd:85a3::0001",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByFqdn(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropFqdnFile = "../tests/testsdata/filtering_fqdn.txt"

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "www.microsoft.com"
	if result, _ := filtering.dropFqdnFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = testURL1
	if result, _ := filtering.dropFqdnFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByDomainRegex(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropDomainFile = "../tests/testsdata/filtering_fqdn_regex.txt"

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if result, _ := filtering.dropDomainRegexFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = testURL2
	if result, _ := filtering.dropDomainRegexFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "github.fr"
	if result, _ := filtering.dropDomainRegexFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepDomain(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()

	outChans := []chan dnsutils.DNSMessage{}

	// file contains google.fr, test.github.com
	config.Filtering.Enable = true
	config.Filtering.KeepFqdnFile = "../tests/testsdata/filtering_keep_domains.txt"

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if result, _ := filtering.keepFqdnFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "example.com"
	if result, _ := filtering.keepFqdnFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = testURL2
	if result, _ := filtering.keepFqdnFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "google.fr"
	if result, _ := filtering.keepFqdnFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepDomainRegex(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()

	outChans := []chan dnsutils.DNSMessage{}

	/* file contains:
	(mail|sheets).google.com$
	test.github.com$
	.+.google.com$
	*/
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = "../tests/testsdata/filtering_keep_domains_regex.txt"

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)

	// get tranforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if result, _ := filtering.keepDomainRegexFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.google.com.ru"
	if result, _ := filtering.keepDomainRegexFilter(&dm); result != ReturnDrop {

		// If this passes then these are not terminated.
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = testURL2
	if result, _ := filtering.keepDomainRegexFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.github.com.malware.ru"
	if result, _ := filtering.keepDomainRegexFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringMultipleFilters(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropDomainFile = "../tests/testsdata/filtering_fqdn_regex.txt"
	config.Filtering.DropQueryIPFile = "../tests/testsdata/filtering_queryip.txt"

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)
	subtransforms, _ := filtering.GetTransforms()

	if len(subtransforms) != 2 {
		t.Errorf("invalid number of subtransforms enabled")
	}
}
