package subprocessors

import (
	"regexp"

	"github.com/dmachard/go-dnslogger/dnsutils"
)

type FilteringProcessor struct {
	config             *dnsutils.Config
	ignoreQnamePattern *regexp.Regexp
	ignoreQname        bool
}

func NewFilteringProcessor(config *dnsutils.Config) FilteringProcessor {
	d := FilteringProcessor{
		config: config,
	}

	if len(d.config.Subprocessors.Filtering.IgnoreQname) > 0 {
		d.ignoreQnamePattern = regexp.MustCompile(d.config.Subprocessors.Filtering.IgnoreQname)
		d.ignoreQname = true
	}

	return d
}

func (p *FilteringProcessor) Ignore(dm *dnsutils.DnsMessage) bool {
	// ignore queries ?
	if !p.config.Subprocessors.Filtering.LogQueries && dm.Type == "query" {
		return true
	}

	// ignore replies ?
	if !p.config.Subprocessors.Filtering.LogReplies && dm.Type == "reply" {
		return true
	}

	// ignore qname ?
	if p.ignoreQname {
		if p.ignoreQnamePattern.MatchString(dm.Qname) {
			return true
		}
	}

	return false
}
