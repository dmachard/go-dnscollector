package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type RelabelProcessor struct {
	config      *pkgconfig.ConfigTransformers
	logger      *logger.Logger
	name        string
	instance    int
	outChannels []chan dnsutils.DNSMessage
	logInfo     func(msg string, v ...interface{})
	logError    func(msg string, v ...interface{})
}

func NewRelabelSubprocessor(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{})) RelabelProcessor {
	s := RelabelProcessor{
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

func (p *RelabelProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config
}

func (p *RelabelProcessor) InitDNSMessage(dm *dnsutils.DNSMessage) {}

func (p *RelabelProcessor) IsEnabled() bool {
	return p.config.Relabeling.Enable
}

func (p *RelabelProcessor) AddLabelConfig(dm *dnsutils.DNSMessage) int {
	if p.config.Relabeling.Enable {
		for _, label := range p.config.Relabeling.Rename {
			dm.RelabelingRename = append(dm.RelabelingRename, dnsutils.TransformRelabeling{
				Regex:       label.Regex,
				Replacement: label.Replacement})
		}
		for _, label := range p.config.Relabeling.Remove {
			dm.RelabelingRemove = append(dm.RelabelingRemove, dnsutils.TransformRelabeling{
				Regex:       label.Regex,
				Replacement: label.Replacement})
		}
	}
	return ReturnSuccess
}
