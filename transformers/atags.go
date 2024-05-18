package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ATagsTransform struct {
	Transformer
}

func NewATagsTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) ATagsTransform {
	return ATagsTransform{Transformer: NewTransformer(config, logger, name, instance, nextWorkers)}
}

func (t *ATagsTransform) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.ATags != nil {
		return
	}
	dm.ATags = &dnsutils.TransformATags{Tags: []string{}}
}

func (t *ATagsTransform) IsEnabled() bool { return t.config.ATags.Enable }

func (t *ATagsTransform) GetTransforms() []func(dm *dnsutils.DNSMessage) int {
	if t.IsEnabled() {
		t.LogInfo("transformer=atags is enabled")
		t.activeTransforms = append(t.activeTransforms, t.AddTags)
	}
	return t.activeTransforms
}

func (t *ATagsTransform) AddTags(dm *dnsutils.DNSMessage) int {
	if t.IsEnabled() {
		dm.ATags.Tags = append(dm.ATags.Tags, t.config.ATags.Tags...)
	}
	return ReturnSuccess
}
