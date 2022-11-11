package transformers

import (
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type SuspiciousTransform struct {
	config       *dnsutils.Config
	logger       *logger.Logger
	name         string
	CommonQtypes map[string]bool
}

func NewSuspiciousSubprocessor(config *dnsutils.Config, logger *logger.Logger, name string) SuspiciousTransform {
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
	for _, v := range p.config.Transformers.Suspicious.CommonQtypes {
		p.CommonQtypes[v] = true
	}
}

func (p *SuspiciousTransform) IsEnabled() bool {
	return p.config.Transformers.Suspicious.Enable
}

func (p *SuspiciousTransform) LogInfo(msg string, v ...interface{}) {
	p.logger.Info("Transform Suspicious - "+msg, v...)
}

func (p *SuspiciousTransform) LogError(msg string, v ...interface{}) {
	p.logger.Error("Transform Suspicious - "+msg, v...)
}

func (p *SuspiciousTransform) CheckIfSuspicious(dm *dnsutils.DnsMessage) {

	// dns decoding error?
	if dm.DNS.MalformedPacket {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.Flags.MalformedPacket = true
	}

	// long domain name ?
	if len(dm.DNS.Qname) > p.config.Transformers.Suspicious.ThresholdQnameLen {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.Flags.LongDomain = true
	}

	// large packet size ?
	if dm.DNS.Length > p.config.Transformers.Suspicious.ThresholdPacketLen {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.Flags.LargePacket = true
	}

	// uncommon qtype?
	if _, found := p.CommonQtypes[dm.DNS.Qtype]; !found {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.Flags.UncommonQtypes = true
	}

	// count the number of labels in qname
	if strings.Count(dm.DNS.Qname, ".") > p.config.Transformers.Suspicious.ThresholdMaxLabels {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.Flags.ExcessiveNumberLabels = true
	}

	// search for unallowed characters
	for _, v := range p.config.Transformers.Suspicious.UnallowedChars {
		if strings.Contains(dm.DNS.Qname, v) {
			dm.Suspicious.Score += 1.0
			dm.Suspicious.Flags.UnallowedChars = true
			break
		}
	}
}
