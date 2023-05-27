package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type ExtractProcessor struct {
	config      *dnsutils.ConfigTransformers
	logger      *logger.Logger
	name        string
	instance    int
	outChannels []chan dnsutils.DnsMessage
	logInfo     func(msg string, v ...interface{})
	logError    func(msg string, v ...interface{})
}

func NewExtractSubprocessor(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DnsMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{})) ExtractProcessor {
	s := ExtractProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		instance:    instance,
		outChannels: outChannels,
		logInfo:     logInfo,
		logError:    logError,
	}

	return s
}

func (p *ExtractProcessor) InitDnsMessage(dm *dnsutils.DnsMessage) {
	if dm.Extracted == nil {
		dm.Extracted = &dnsutils.TransformExtracted{
			Base64Payload: []byte("-"),
		}
	}
}

func (s *ExtractProcessor) IsEnabled() bool {
	return s.config.Extract.Enable
}

func (s *ExtractProcessor) AddBase64Payload(dm *dnsutils.DnsMessage) []byte {
	// Encode to base64 is done automatically by the json encoder ([]byte)
	return dm.DNS.Payload
}
