package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
)

type ExtractProcessor struct {
	config *dnsutils.ConfigTransformers
}

func NewExtractSubprocessor(config *dnsutils.ConfigTransformers) ExtractProcessor {
	s := ExtractProcessor{
		config: config,
	}

	return s
}

func (p *ExtractProcessor) InitDnsMessage(dm *dnsutils.DnsMessage) {
	dm.Extracted = &dnsutils.Extracted{
		Base64Payload: []byte("-"),
	}
}

func (s *ExtractProcessor) IsEnabled() bool {
	return s.config.Extract.Enable
}

func (s *ExtractProcessor) AddBase64Payload(dm *dnsutils.DnsMessage) []byte {
	// Encode to base64 is done automatically by the json encoder ([]byte)
	return dm.DNS.Payload
}
