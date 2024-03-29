package transformers

import (
	"fmt"
	"regexp"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type RelabelProcessor struct {
	config          *pkgconfig.ConfigTransformers
	logger          *logger.Logger
	name            string
	instance        int
	outChannels     []chan dnsutils.DNSMessage
	LogInfo         func(msg string, v ...interface{})
	LogError        func(msg string, v ...interface{})
	RelabelingRules []dnsutils.RelabelingRule
}

func NewRelabelTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage) RelabelProcessor {
	s := RelabelProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		instance:    instance,
		outChannels: outChannels,
	}

	s.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - relabeling - ", name, instance)
		logger.Info(log+msg, v...)
	}

	s.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - relabeling - ", name, instance)
		logger.Error(log+msg, v...)
	}

	s.Precompile()
	return s
}

func (p *RelabelProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config
}

func (p *RelabelProcessor) Precompile() {
	// Pre-compile regular expressions
	for _, label := range p.config.Relabeling.Rename {
		p.RelabelingRules = append(p.RelabelingRules, dnsutils.RelabelingRule{
			Regex:       regexp.MustCompile(label.Regex),
			Replacement: label.Replacement,
			Action:      "rename",
		})
	}
	for _, label := range p.config.Relabeling.Remove {
		p.RelabelingRules = append(p.RelabelingRules, dnsutils.RelabelingRule{
			Regex:       regexp.MustCompile(label.Regex),
			Replacement: label.Replacement,
			Action:      "drop",
		})
	}
}

func (p *RelabelProcessor) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.Relabeling == nil {
		dm.Relabeling = &dnsutils.TransformRelabeling{
			Rules: p.RelabelingRules,
		}
	}
}

func (p *RelabelProcessor) IsEnabled() bool {
	return p.config.Relabeling.Enable
}
