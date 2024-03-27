package transformers

import (
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
	logInfo         func(msg string, v ...interface{})
	logError        func(msg string, v ...interface{})
	RelabelingRules []dnsutils.RelabelingRule
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
