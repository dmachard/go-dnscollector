package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestReduceQname(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfig()
	config.Subprocessors.UserPrivacy.MinimazeQname = true

	// init the processor
	privQname := NewQnameReducerSubprocessor(config)

	if !privQname.IsEnabled() {
		t.Errorf("feature not enabled")
	}

	qname := "www.google.com"
	ret := privQname.Minimaze(qname)
	if ret != "google.com" {
		t.Errorf("Qname minimization failed, got %s", ret)
	}

	qname = "localhost"
	ret = privQname.Minimaze(qname)
	if ret != "localhost" {
		t.Errorf("Qname minimization failed, got %s", ret)
	}

	qname = "localhost.domain.local.home"
	ret = privQname.Minimaze(qname)
	if ret != "local.home" {
		t.Errorf("Qname minimization failed, got %s", ret)
	}
}
