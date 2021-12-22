package subprocessors

import (
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
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
	i := strings.LastIndex(qname, ".")
	if i == -1 {
		return qname
	}

	j := strings.LastIndex(qname[:i], ".")
	if j == -1 {
		return qname
	}
	return qname[j+1:]
}
