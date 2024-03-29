package transformers

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ExtractProcessor struct {
	config      *pkgconfig.ConfigTransformers
	logger      *logger.Logger
	name        string
	instance    int
	outChannels []chan dnsutils.DNSMessage
	LogInfo     func(msg string, v ...interface{})
	LogError    func(msg string, v ...interface{})
}

func NewExtractTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage) ExtractProcessor {
	s := ExtractProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		instance:    instance,
		outChannels: outChannels,
	}
	s.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - extract - ", name, instance)
		logger.Info(log+msg, v...)
	}

	s.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - extract - ", name, instance)
		logger.Error(log+msg, v...)
	}
	return s
}

func (p *ExtractProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config
}

func (p *ExtractProcessor) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.Extracted == nil {
		dm.Extracted = &dnsutils.TransformExtracted{
			Base64Payload: []byte("-"),
		}
	}
}

func (p *ExtractProcessor) IsEnabled() bool {
	return p.config.Extract.Enable
}

func (p *ExtractProcessor) AddBase64Payload(dm *dnsutils.DNSMessage) []byte {
	// Encode to base64 is done automatically by the json encoder ([]byte)
	return dm.DNS.Payload
}
