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
	config.ATags.AddTags = append(config.ATags.AddTags, "tag1")
	config.ATags.AddTags = append(config.ATags.AddTags, "tag2")

	// init the processor
	outChans := []chan dnsutils.DNSMessage{}
	atags := NewATagsTransform(config, logger.New(false), "test", 0, outChans)

	// add tags
	dm := dnsutils.GetFakeDNSMessage()
	atags.addTags(&dm)

	// check results
	if dm.ATags == nil {
		t.Errorf("DNSMessage.Atags should be not nil")
	}
	if len(dm.ATags.Tags) != 2 {
		t.Errorf("incorrect number of tag in DNSMessage")
	}
}
