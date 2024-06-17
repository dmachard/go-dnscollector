package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ExtractTransform struct {
	GenericTransformer
}

func NewExtractTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *ExtractTransform {
	t := &ExtractTransform{GenericTransformer: NewTransformer(config, logger, "extract", name, instance, nextWorkers)}
	return t
}

func (t *ExtractTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Extract.AddPayload {
		subtransforms = append(subtransforms, Subtransform{name: "extract:add-base64payload", processFunc: t.addBase64Payload})
	}
	return subtransforms, nil
}

func (t *ExtractTransform) addBase64Payload(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Extracted == nil {
		dm.Extracted = &dnsutils.TransformExtracted{Base64Payload: []byte("-")}
	}

	dm.Extracted.Base64Payload = dm.DNS.Payload
	return ReturnKeep, nil
}
