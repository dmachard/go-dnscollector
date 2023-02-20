package transformers

import (
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type SuspiciousTransform struct {
	config       *dnsutils.ConfigTransformers
	logger       *logger.Logger
	name         string
	CommonQtypes map[string]bool
}

func NewSuspiciousSubprocessor(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string) SuspiciousTransform {
	d := SuspiciousTransform{
		config:       config,
		logger:       logger,
		name:         name,
		CommonQtypes: make(map[string]bool),
	}

	d.ReadConfig()

	return d
}

func (p *SuspiciousTransform) ReadConfig() {
	for _, v := range p.config.Suspicious.CommonQtypes {
		p.CommonQtypes[v] = true
	}
}

func (p *SuspiciousTransform) IsEnabled() bool {
	return p.config.Suspicious.Enable
}

func (p *SuspiciousTransform) LogInfo(msg string, v ...interface{}) {
	p.logger.Info("Transform Suspicious - "+msg, v...)
}

func (p *SuspiciousTransform) LogError(msg string, v ...interface{}) {
	p.logger.Error("Transform Suspicious - "+msg, v...)
}

func (p *SuspiciousTransform) InitDnsMessage(dm *dnsutils.DnsMessage) {
	dm.Suspicious = &dnsutils.Suspicious{
		Score:                 0.0,
		MalformedPacket:       false,
		LargePacket:           false,
		LongDomain:            false,
		SlowDomain:            false,
		UnallowedChars:        false,
		UncommonQtypes:        false,
		ExcessiveNumberLabels: false,
	}
}

func (p *SuspiciousTransform) CheckIfSuspicious(dm *dnsutils.DnsMessage) {

	if dm.Suspicious == nil {
		p.LogError("transformer is not properly initialized")
		return
	}

	// dns decoding error?
	if dm.DNS.MalformedPacket {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.MalformedPacket = true
	}

	// long domain name ?
	if len(dm.DNS.Qname) > p.config.Suspicious.ThresholdQnameLen {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.LongDomain = true
	}

	// large packet size ?
	if dm.DNS.Length > p.config.Suspicious.ThresholdPacketLen {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.LargePacket = true
	}

	// uncommon qtype?
	if _, found := p.CommonQtypes[dm.DNS.Qtype]; !found {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.UncommonQtypes = true
	}

	// count the number of labels in qname
	if strings.Count(dm.DNS.Qname, ".") > p.config.Suspicious.ThresholdMaxLabels {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.ExcessiveNumberLabels = true
	}

	// search for unallowed characters
	for _, v := range p.config.Suspicious.UnallowedChars {
		if strings.Contains(dm.DNS.Qname, v) {
			dm.Suspicious.Score += 1.0
			dm.Suspicious.UnallowedChars = true
			break
		}
	}
}
