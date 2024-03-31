package transformers

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ATagsProcessor struct {
	config            *pkgconfig.ConfigTransformers
	logger            *logger.Logger
	outChannels       []chan dnsutils.DNSMessage
	LogInfo, LogError func(msg string, v ...interface{})
}

func NewATagsTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage) ATagsProcessor {
	s := ATagsProcessor{config: config, logger: logger, outChannels: outChannels}

	s.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - atags - ", name, instance)
		logger.Info(log+msg, v...)
	}

	s.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - atags - ", name, instance)
		logger.Error(log+msg, v...)
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
