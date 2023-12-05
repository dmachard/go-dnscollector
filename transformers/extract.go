package transformers

import (
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
	logInfo     func(msg string, v ...interface{})
	logError    func(msg string, v ...interface{})
}

func NewExtractSubprocessor(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage,
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
