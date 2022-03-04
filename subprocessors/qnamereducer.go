package subprocessors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"golang.org/x/net/publicsuffix"
)

type QnameReducer struct {
	config  *dnsutils.Config
	enabled bool
}

func NewQnameReducerSubprocessor(config *dnsutils.Config) QnameReducer {
	s := QnameReducer{
		config: config,
	}

	s.ReadConfig()

	return s
}

func (s *QnameReducer) ReadConfig() {
	s.enabled = s.config.Subprocessors.UserPrivacy.MinimazeQname
}

func (s *QnameReducer) IsEnabled() bool {
	return s.enabled
}

func (s *QnameReducer) Minimaze(qname string) string {
	if etpo, err := publicsuffix.EffectiveTLDPlusOne(qname); err == nil {
		return etpo
	}

	return qname
}
