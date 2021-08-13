package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnslogger/dnsutils"
)

func TestFilteringQR(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.Filtering.LogQueries = false
	config.Subprocessors.Filtering.LogReplies = false

	// init subproccesor
	filtering := NewFilteringProcessor(config)

	dm := dnsutils.GetFakeDnsMessage()
	if !filtering.Ignore(&dm) {
		t.Errorf("dns query should be ignored")
	}

	dm.Type = "reply"
	if !filtering.Ignore(&dm) {
		t.Errorf("dns reply should be ignored")
	}

}

func TestFilteringQname(t *testing.T) {
	// config
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.Filtering.IgnoreQname = "^*.collector$"
	// init subproccesor
	filtering := NewFilteringProcessor(config)

	dm := dnsutils.GetFakeDnsMessage()
	if !filtering.Ignore(&dm) {
		t.Errorf("dns query should be ignored regex failed got: %s", dm.Qname)
	}
}
