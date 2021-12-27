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
