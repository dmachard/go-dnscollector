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

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	if !filtering.CheckIfDrop(&dm) {
		t.Errorf("dns query should be ignored")
	}

	dm.DNS.Type = dnsutils.DNSReply
	if !filtering.CheckIfDrop(&dm) {
		t.Errorf("dns reply should be ignored")
	}

}

func TestFilteringByRcodeNOERROR(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropRcodes = []string{"NOERROR"}

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadRcodes()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped")
	}

}

func TestFilteringByRcodeEmpty(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropRcodes = []string{}

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadRcodes()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepQueryIp(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.KeepQueryIPFile = "../testsdata/filtering_queryip_keep.txt"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadQueryIPList()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "192.168.0.1"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.168.1.10"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.3.2.1" // kept by subnet
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

}

func TestFilteringByDropQueryIp(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropQueryIPFile = "../testsdata/filtering_queryip.txt"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadQueryIPList()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "192.168.0.1"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.168.1.15"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.0.2.3" // dropped by subnet
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

}

func TestFilteringByKeepRdataIp(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.KeepRdataFile = "../testsdata/filtering_rdataip_keep.txt"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadrDataIPList()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.0.1",
		},
	}
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.1.10",
		},
	}
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.1.11", // included in subnet
		},
	}
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.0.2.3", // dropped by subnet
		},
	}
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.0.2.1",
		},
	}
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2001:db8:85a3::8a2e:370:7334",
		},
	}
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2041::7334",
		},
	}
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2001:0dbd:85a3::0001",
		},
	}
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByFqdn(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropFqdnFile = "../testsdata/filtering_fqdn.txt"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadDomainsList()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "www.microsoft.com"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = testURL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByDomainRegex(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropDomainFile = "../testsdata/filtering_fqdn_regex.txt"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadDomainsList()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = testURL2
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "github.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepDomain(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// file contains google.fr, test.github.com
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = "../testsdata/filtering_keep_domains.txt"

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadDomainsList()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "example.com"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = testURL2
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "google.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepDomainRegex(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	/* file contains:
	(mail|sheets).google.com$
	test.github.com$
	.+.google.com$
	*/
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = "../testsdata/filtering_keep_domains_regex.txt"

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadDomainsList()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.google.com.ru"
	if filtering.CheckIfDrop(&dm) == false {

		// If this passes then these are not terminated.
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = testURL2
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.github.com.malware.ru"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByDownsampleDisabled(t *testing.T) {
	// config, down sample is disabled by default
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadActiveFilters()

	// init DNS Message
	dm := dnsutils.GetFakeDNSMessage()

	// test for default behavior when downsample is set to 0
	filtering = NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampling rate is set to 0 and should not downsample.")
	}
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampling rate is set to 0 and should not downsample.")
	}
}

func TestFilteringByDownsample(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.Downsample = 2

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadActiveFilters()

	// init DNS Message
	dm := dnsutils.GetFakeDNSMessage()

	// filtering.downsampleCount
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! downsampled should exclude first hit.")
	}

	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampled one record and then should include the next if downsample rate is 2")
	}

	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! downsampled should exclude first hit.")
	}

	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampled one record and then should include the next if downsample rate is 2")
	}
}

func TestFilteringByDownsampleUpdateJSONModel(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.Downsample = 2

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadActiveFilters()

	// init DNS Message
	dm := dnsutils.GetFakeDNSMessage()
	filtering.InitDNSMessage(&dm)

	// filtering.downsampleCount
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! downsampled should exclude first hit.")
	}

	// test json model

	jsonRef := dnsutils.DNSMessage{
		Filtering: &dnsutils.TransformFiltering{SampleRate: 2},
	}
	if dm.Filtering.SampleRate != jsonRef.Filtering.SampleRate {
		t.Errorf("DNS message invalid sample rate: Want=%d, Get=%d", jsonRef.Filtering.SampleRate, dm.Filtering.SampleRate)
	}
}

func TestFilteringMultipleFilters(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropDomainFile = "../testsdata/filtering_fqdn_regex.txt"
	config.Filtering.DropQueryIPFile = "../testsdata/filtering_queryip.txt"

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	filtering.LoadQueryIPList()
	filtering.LoadDomainsList()
	filtering.LoadActiveFilters()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = testURL2
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "github.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.168.1.15"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.0.2.3" // dropped by subnet
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}
