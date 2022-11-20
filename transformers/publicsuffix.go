package transformers

import (
	"errors"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	publicsuffixlist "golang.org/x/net/publicsuffix"
)

type PublicSuffixProcessor struct {
	config *dnsutils.ConfigTransformers
}

func NewPublicSuffixSubprocessor(config *dnsutils.ConfigTransformers) PublicSuffixProcessor {
	s := PublicSuffixProcessor{
		config: config,
	}

	return s
}

func (s *PublicSuffixProcessor) IsEnabled() bool {
	return s.config.PublicSuffix.Enable
}

func (s *PublicSuffixProcessor) GetEffectiveTld(qname string) (string, error) {

	// PublicSuffix is case sensitive.
	// remove ending dot ?
	qname = strings.ToLower(qname)
	qname = strings.TrimSuffix(qname, ".")

	// search
	etld, icann := publicsuffixlist.PublicSuffix(qname)
	if icann {
		return etld, nil
	}
	return "", errors.New("ICANN Unmanaged")
}

func (s *PublicSuffixProcessor) GetEffectiveTldPlusOne(qname string) (string, error) {
	// PublicSuffix is case sensitive.
	// remove ending dot ?
	qname = strings.ToLower(qname)
	qname = strings.TrimSuffix(qname, ".")

	return publicsuffixlist.EffectiveTLDPlusOne(qname)
}
