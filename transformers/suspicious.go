package transformers

import (
	"regexp"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type SuspiciousTransform struct {
	GenericTransformer
	commonQtypes          map[string]bool
	whitelistDomainsRegex map[string]*regexp.Regexp
}

func NewSuspiciousTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *SuspiciousTransform {
	t := &SuspiciousTransform{GenericTransformer: NewTransformer(config, logger, "suspicious", name, instance, nextWorkers)}
	t.commonQtypes = make(map[string]bool)
	t.whitelistDomainsRegex = make(map[string]*regexp.Regexp)
	return t
}

func (t *SuspiciousTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}

	// cleanup maps
	for key := range t.commonQtypes {
		delete(t.commonQtypes, key)
	}
	for key := range t.whitelistDomainsRegex {
		delete(t.whitelistDomainsRegex, key)
	}

	// load maps
	for _, v := range t.config.Suspicious.CommonQtypes {
		t.commonQtypes[v] = true
	}
	for _, v := range t.config.Suspicious.WhitelistDomains {
		t.whitelistDomainsRegex[v] = regexp.MustCompile(v)
	}

	if t.config.Suspicious.Enable {
		subtransforms = append(subtransforms, Subtransform{name: "suspicious:check", processFunc: t.checkIfSuspicious})
	}
	return subtransforms, nil
}

func (t *SuspiciousTransform) checkIfSuspicious(dm *dnsutils.DNSMessage) (int, error) {

	if dm.Suspicious == nil {
		dm.Suspicious = &dnsutils.TransformSuspicious{}
	}

	// ignore some domains ?
	for _, d := range t.whitelistDomainsRegex {
		if d.MatchString(dm.DNS.Qname) {
			return ReturnKeep, nil
		}
	}

	// dns decoding error?
	if dm.DNS.MalformedPacket {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.MalformedPacket = true
	}

	// long domain name ?
	if len(dm.DNS.Qname) > t.config.Suspicious.ThresholdQnameLen {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.LongDomain = true
	}

	// large packet size ?
	if dm.DNS.Length > t.config.Suspicious.ThresholdPacketLen {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.LargePacket = true
	}

	// slow domain name resolution ?
	if dm.DNSTap.Latency > t.config.Suspicious.ThresholdSlow {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.SlowDomain = true
	}

	// uncommon qtype?
	if _, found := t.commonQtypes[dm.DNS.Qtype]; !found {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.UncommonQtypes = true
	}

	// count the number of labels in qname
	if strings.Count(dm.DNS.Qname, ".") > t.config.Suspicious.ThresholdMaxLabels {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.ExcessiveNumberLabels = true
	}

	// search for unallowed characters
	for _, v := range t.config.Suspicious.UnallowedChars {
		if strings.Contains(dm.DNS.Qname, v) {
			dm.Suspicious.Score += 1.0
			dm.Suspicious.UnallowedChars = true
			break
		}
	}

	return ReturnKeep, nil
}
