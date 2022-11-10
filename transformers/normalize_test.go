package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestNormalizeLowercaseQname(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfig()
	config.Transformers.Normalize.Enable = true
	config.Transformers.Normalize.QnameLowerCase = true

	// init the processor
	qnameNorm := NewNormalizeSubprocessor(config)

	qname := "www.Google.Com"
	ret := qnameNorm.Lowercase(qname)
	if ret != "google.com" {
		t.Errorf("Qname to lowercase failed, got %s", ret)
	}
}
