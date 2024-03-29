package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestATags_AddTag(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.ATags.Enable = true
	config.ATags.Tags = append(config.ATags.Tags, "tag1")
	config.ATags.Tags = append(config.ATags.Tags, "tag2")

	// init the processor
	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}
	transform := NewATagsTransform(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	if !transform.IsEnabled() {
		t.Errorf("subprocessor should be enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()

	transform.InitDNSMessage(&dm)
	if dm.ATags == nil {
		t.Errorf("DNSMessage.Atags should be not nil")
	}

	transform.AddTags(&dm)
	if len(dm.ATags.Tags) != 2 {
		t.Errorf("incorrect number of tag in DNSMessage")
	}
}
