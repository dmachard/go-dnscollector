package transformers

import (
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestRewrite_UpdateFields(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Rewrite.Enable = true
	config.Rewrite.Identifiers = make(map[string]interface{})
	config.Rewrite.Identifiers["dnstap.identity"] = "testidentity"

	// init the processor
	outChans := []chan dnsutils.DNSMessage{}
	rewrite := NewRewriteTransform(config, logger.New(false), "test", 0, outChans)

	// get fake
	dm := dnsutils.GetFakeDNSMessage()

	rewrite.GetTransforms()
	returnCode, err := rewrite.UpdateValues(&dm)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v, want keep(%v)", returnCode, ReturnKeep)
	}

	if dm.DNSTap.Identity != "testidentity" {
		t.Errorf("Want testidentity, got %v", dm.DNSTap.Identity)
	}
}

func TestRewrite_UpdateFields_InvalidType(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Rewrite.Enable = true
	config.Rewrite.Identifiers = make(map[string]interface{})
	config.Rewrite.Identifiers["dnstap.identity"] = 0

	// init the processor
	outChans := []chan dnsutils.DNSMessage{}
	rewrite := NewRewriteTransform(config, logger.New(false), "test", 0, outChans)

	// get fake
	dm := dnsutils.GetFakeDNSMessage()

	rewrite.GetTransforms()
	_, err := rewrite.UpdateValues(&dm)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "unable to set value") {
		t.Errorf("invalid error: %s", err)
	}
}
