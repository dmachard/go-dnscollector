package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ATagsTransform struct {
	GenericTransformer
}

func NewATagsTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *ATagsTransform {
	t := &ATagsTransform{GenericTransformer: NewTransformer(config, logger, "atags", name, instance, nextWorkers)}
	return t
}

func (t *ATagsTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if len(t.config.ATags.AddTags) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "atags:add", processFunc: t.addTags})
	}
	return subtransforms, nil
}

func (t *ATagsTransform) addTags(dm *dnsutils.DNSMessage) (int, error) {
	if dm.ATags == nil {
		dm.ATags = &dnsutils.TransformATags{Tags: []string{}}
	}

	dm.ATags.Tags = append(dm.ATags.Tags, t.config.ATags.AddTags...)
	return ReturnKeep, nil
}
