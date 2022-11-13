package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestNormalizeLowercaseQname(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true

	// init the processor
	qnameNorm := NewNormalizeSubprocessor(config)

	qname := "www.Google.Com"
	ret := qnameNorm.Lowercase(qname)
	if ret != "www.google.com" {
		t.Errorf("Qname to lowercase failed, got %s", ret)
	}
}
