package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ATagsProcessor struct {
	Transformer
}

func NewATagsTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) ATagsProcessor {
	return ATagsProcessor{Transformer: NewTransformer(config, logger, name, instance, nextWorkers)}
}

func (t *ATagsProcessor) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.ATags == nil {
		dm.ATags = &dnsutils.TransformATags{Tags: []string{}}
	}
}

func (t *ATagsProcessor) IsEnabled() bool { return t.config.ATags.Enable }

func (t *ATagsProcessor) AddTags(dm *dnsutils.DNSMessage) int {
	if t.IsEnabled() {
		dm.ATags.Tags = append(dm.ATags.Tags, t.config.ATags.Tags...)
	}
	return ReturnSuccess
}
