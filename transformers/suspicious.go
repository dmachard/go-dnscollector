package transformers

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type SuspiciousTransform struct {
	config                *pkgconfig.ConfigTransformers
	logger                *logger.Logger
	name                  string
	CommonQtypes          map[string]bool
	whitelistDomainsRegex map[string]*regexp.Regexp
	instance              int
	outChannels           []chan dnsutils.DNSMessage
	logInfo               func(msg string, v ...interface{})
	logError              func(msg string, v ...interface{})
}

func NewSuspiciousTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{}),
) SuspiciousTransform {
	d := SuspiciousTransform{
		config:                config,
		logger:                logger,
		name:                  name,
		CommonQtypes:          make(map[string]bool),
		whitelistDomainsRegex: make(map[string]*regexp.Regexp),
		instance:              instance,
		outChannels:           outChannels,
		logInfo:               logInfo,
		logError:              logError,
	}

	d.ReadConfig()

	return d
}

func (p *SuspiciousTransform) ReadConfig() {
	// cleanup maps
	for key := range p.CommonQtypes {
		delete(p.CommonQtypes, key)
	}
	for key := range p.whitelistDomainsRegex {
		delete(p.whitelistDomainsRegex, key)
	}

	// load maps
	for _, v := range p.config.Suspicious.CommonQtypes {
		p.CommonQtypes[v] = true
	}
	for _, v := range p.config.Suspicious.WhitelistDomains {
		p.whitelistDomainsRegex[v] = regexp.MustCompile(v)
	}
}

func (p *SuspiciousTransform) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config

	p.ReadConfig()
}

func (p *SuspiciousTransform) IsEnabled() bool {
	return p.config.Suspicious.Enable
}

func (p *SuspiciousTransform) LogInfo(msg string, v ...interface{}) {
	log := fmt.Sprintf("suspicious#%d - ", p.instance)
	p.logInfo(log+msg, v...)
}

func (p *SuspiciousTransform) LogError(msg string, v ...interface{}) {
	log := fmt.Sprintf("suspicious#%d - ", p.instance)
	p.logError(log+msg, v...)
}

func (p *SuspiciousTransform) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.Suspicious == nil {
		dm.Suspicious = &dnsutils.TransformSuspicious{
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
}

func (p *SuspiciousTransform) CheckIfSuspicious(dm *dnsutils.DNSMessage) {

	if dm.Suspicious == nil {
		p.LogError("transformer is not properly initialized")
		return
	}

	// ignore some domains ?
	for _, d := range p.whitelistDomainsRegex {
		if d.MatchString(dm.DNS.Qname) {
			return
		}
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

	// slow domain name resolution ?
	if dm.DNSTap.Latency > p.config.Suspicious.ThresholdSlow {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.SlowDomain = true
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
