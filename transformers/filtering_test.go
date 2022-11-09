package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

const (
	TEST_URL1 = "mail.google.com"
	TEST_URL2 = "test.github.com"
)

func TestFilteringQR(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Filtering.LogQueries = false
	config.Transformers.Filtering.LogReplies = false

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	if !filtering.CheckIfDrop(&dm) {
		t.Errorf("dns query should be ignored")
	}

	dm.DNS.Type = dnsutils.DnsReply
	if !filtering.CheckIfDrop(&dm) {
		t.Errorf("dns reply should be ignored")
	}

}

func TestFilteringByRcodeNOERROR(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Filtering.DropRcodes = []string{"NOERROR"}

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped")
	}

}

func TestFilteringByRcodeEmpty(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Filtering.DropRcodes = []string{}

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByQueryIp(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Filtering.DropQueryIpFile = "../testsdata/filtering_queryip.txt"
	config.Transformers.Filtering.KeepQueryIpFile = "../testsdata/filtering_queryip_keep.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.NetworkInfo.QueryIp = "192.168.0.1"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.168.1.15"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.168.1.10" // Both in drop and keep, so keep
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.0.2.3" // dropped by subnet
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.0.2.1" // dropped by subnet, but explicitly in keep
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

}

func TestFilteringByFqdn(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Filtering.DropFqdnFile = "../testsdata/filtering_fqdn.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = "www.microsoft.com"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByDomainRegex(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Filtering.DropDomainFile = "../testsdata/filtering_fqdn_regex.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = TEST_URL2
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
	config := dnsutils.GetFakeConfig()

	// file contains google.fr, test.github.com
	config.Transformers.Filtering.KeepDomainFile = "../testsdata/filtering_keep_domains.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "example.com"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = TEST_URL2
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
	config := dnsutils.GetFakeConfig()

	/* file contains:
	(mail|sheets).google.com$
	test.github.com$
	.+.google.com$
	*/
	config.Transformers.Filtering.KeepDomainFile = "../testsdata/filtering_keep_domains_regex.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.google.com.ru"
	if filtering.CheckIfDrop(&dm) == false {

		// If this passes then these are not terminated.
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = TEST_URL2
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.github.com.malware.ru"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByDownsample(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Filtering.Downsample = 2

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")
	dm := dnsutils.GetFakeDnsMessage()

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

	// test for default behavior when downsample is set to 0
	config.Transformers.Filtering.Downsample = 0
	filtering = NewFilteringProcessor(config, logger.New(false), "test")

	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampling rate is set to 0 and should not downsample.")
	}
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped! downsampling rate is set to 0 and should not downsample.")
	}

}

func TestFilteringMultipleFilters(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Transformers.Filtering.DropDomainFile = "../testsdata/filtering_fqdn_regex.txt"
	config.Transformers.Filtering.DropQueryIpFile = "../testsdata/filtering_queryip.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = TEST_URL1
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = TEST_URL2
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "github.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.168.1.15"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIp = "192.0.2.3" // dropped by subnet
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}
