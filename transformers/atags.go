package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ATagsProcessor struct {
	config      *pkgconfig.ConfigTransformers
	logger      *logger.Logger
	name        string
	instance    int
	outChannels []chan dnsutils.DNSMessage
	logInfo     func(msg string, v ...interface{})
	logError    func(msg string, v ...interface{})
}

func NewATagsTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{})) ATagsProcessor {
	s := ATagsProcessor{
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

func (p *ATagsProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config
}

func (p *ATagsProcessor) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.ATags == nil {
		dm.ATags = &dnsutils.TransformATags{
			Tags: []string{},
		}

	}
}

func (p *ATagsProcessor) IsEnabled() bool {
	return p.config.ATags.Enable
}

func (p *ATagsProcessor) AddTags(dm *dnsutils.DNSMessage) int {
	if p.config.ATags.Enable {
		dm.ATags.Tags = append(dm.ATags.Tags, p.config.ATags.Tags...)
	}
	return ReturnSuccess
}
