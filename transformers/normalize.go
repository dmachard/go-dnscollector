package transformers

import (
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

type NormalizeProcessor struct {
	config *dnsutils.Config
}

func NewNormalizeSubprocessor(config *dnsutils.Config) NormalizeProcessor {
	s := NormalizeProcessor{
		config: config,
	}

	return s
}

func (s *NormalizeProcessor) IsEnabled() bool {
	return s.config.Transformers.Normalize.Enable
}

func (s *NormalizeProcessor) Lowercase(qname string) string {
	return strings.ToLower(qname)
}
