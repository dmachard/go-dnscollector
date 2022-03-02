package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestFilteringQR(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.Filtering.LogQueries = false
	config.Subprocessors.Filtering.LogReplies = false

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false))

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
	config.Subprocessors.Filtering.DropRcodes = []string{"NOERROR"}

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false))

	dm := dnsutils.GetFakeDnsMessage()
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped")
	}

}

func TestFilteringByRcodeEmpty(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.Filtering.DropRcodes = []string{}

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false))

	dm := dnsutils.GetFakeDnsMessage()
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByQueryIp(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.Filtering.DropQueryIpFile = "../testsdata/filtering_queryip.txt"
	config.Subprocessors.Filtering.KeepQueryIpFile = "../testsdata/filtering_queryip_keep.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false))

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
	config.Subprocessors.Filtering.DropFqdnFile = "../testsdata/filtering_fqdn.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false))

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = "www.microsoft.com"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "mail.google.com"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByDomainRegex(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.Filtering.DropDomainFile = "../testsdata/filtering_fqdn_regex.txt"

	// init subproccesor
	filtering := NewFilteringProcessor(config, logger.New(false))

	dm := dnsutils.GetFakeDnsMessage()
	dm.DNS.Qname = "mail.google.com"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "test.github.com"
	if filtering.CheckIfDrop(&dm) == false {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "github.fr"
	if filtering.CheckIfDrop(&dm) == true {
		t.Errorf("dns query should not be dropped!")
	}
}
