package transformers

import (
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

type NormalizeProcessor struct {
	config *dnsutils.ConfigTransformers
}

func NewNormalizeSubprocessor(config *dnsutils.ConfigTransformers) NormalizeProcessor {
	s := NormalizeProcessor{
		config: config,
	}

	return s
}

func (s *NormalizeProcessor) IsEnabled() bool {
	return s.config.Normalize.Enable
}

func (s *NormalizeProcessor) Lowercase(qname string) string {
	return strings.ToLower(qname)
}
