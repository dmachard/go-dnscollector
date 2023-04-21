package transformers

import (
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	publicsuffixlist "golang.org/x/net/publicsuffix"
)

var (
	DnstapMessage = map[string]string{
		"AUTH_QUERY":         "AQ",
		"AUTH_RESPONSE":      "AR",
		"RESOLVER_QUERY":     "RQ",
		"RESOLVER_RESPONSE":  "RR",
		"CLIENT_QUERY":       "CQ",
		"CLIENT_RESPONSE":    "CR",
		"FORWARDER_QUERY":    "FQ",
		"FORWARDER_RESPONSE": "FR",
		"STUB_QUERY":         "SQ",
		"STUB_RESPONSE":      "SR",
		"TOOL_QUERY":         "TQ",
		"TOOL_RESPONSE":      "TR",
		"UPDATE_QUERY":       "UQ",
		"UPDATE_RESPONSE":    "UR",
		"DNSQueryType":       "Q", // powerdns
		"DNSResponseType":    "R", // powerdns
	}
	DnsQr = map[string]string{
		"QUERY": "Q",
		"REPLY": "R",
	}

	IPversion = map[string]string{
		"INET6": "6",
		"INET":  "4",
	}

	Rcodes = map[string]string{
		"NOERROR":   "0",
		"FORMERR":   "1",
		"SERVFAIL":  "2",
		"NXDOMAIN":  "3",
		"NOIMP":     "4",
		"REFUSED":   "5",
		"YXDOMAIN":  "6",
		"YXRRSET":   "7",
		"NXRRSET":   "8",
		"NOTAUTH":   "9",
		"NOTZONE":   "10",
		"DSOTYPENI": "11",
		"BADSIG":    "16",
		"BADKEY":    "17",
		"BADTIME":   "18",
		"BADMODE":   "19",
		"BADNAME":   "20",
		"BADALG":    "21",
		"BADTRUNC":  "22",
		"BADCOOKIE": "23",
	}
)

type NormalizeProcessor struct {
	config           *dnsutils.ConfigTransformers
	logger           *logger.Logger
	name             string
	activeProcessors []func(dm *dnsutils.DnsMessage) int
}

func NewNormalizeSubprocessor(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string) NormalizeProcessor {
	s := NormalizeProcessor{
		config: config,
		logger: logger,
		name:   name,
	}

	s.LoadActiveProcessors()
	return s
}

func (p *NormalizeProcessor) LogInfo(msg string, v ...interface{}) {
	p.logger.Info("["+p.name+"] transform normalize - "+msg, v...)
}

func (p *NormalizeProcessor) LogError(msg string, v ...interface{}) {
	p.logger.Error("["+p.name+"] transform normalize - "+msg, v...)
}

func (p *NormalizeProcessor) LoadActiveProcessors() {
	if p.config.Normalize.QnameLowerCase {
		p.activeProcessors = append(p.activeProcessors, p.LowercaseQname)
		p.LogInfo("[processor: lowercase] enabled")
	}

	if p.config.Normalize.QuietText {
		p.activeProcessors = append(p.activeProcessors, p.QuietText)
		p.LogInfo("[processor: quiet text] enabled")
	}

	if p.config.Normalize.AddTld {
		p.activeProcessors = append(p.activeProcessors, p.GetEffectiveTld)
		p.LogInfo("[processor: add tld] enabled")
	}
	if p.config.Normalize.AddTldPlusOne {
		p.activeProcessors = append(p.activeProcessors, p.GetEffectiveTldPlusOne)
		p.LogInfo("[processor: add tld+1] enabled")
	}
}

func (s *NormalizeProcessor) IsEnabled() bool {
	return s.config.Normalize.Enable
}

func (p *NormalizeProcessor) InitDnsMessage(dm *dnsutils.DnsMessage) {
	dm.PublicSuffix = &dnsutils.PublicSuffix{
		QnamePublicSuffix:        "-",
		QnameEffectiveTLDPlusOne: "-",
	}
}

func (p *NormalizeProcessor) LowercaseQname(dm *dnsutils.DnsMessage) int {
	dm.DNS.Qname = strings.ToLower(dm.DNS.Qname)

	return RETURN_SUCCESS
}

func (p *NormalizeProcessor) QuietText(dm *dnsutils.DnsMessage) int {
	if v, found := DnstapMessage[dm.DnsTap.Operation]; found {
		dm.DnsTap.Operation = v
	}
	if v, found := DnsQr[dm.DNS.Type]; found {
		dm.DNS.Type = v
	}
	if v, found := IPversion[dm.NetworkInfo.Family]; found {
		dm.NetworkInfo.Family = v
	}
	if v, found := Rcodes[dm.DNS.Rcode]; found {
		dm.DNS.Rcode = v
	}
	return RETURN_SUCCESS
}

func (p *NormalizeProcessor) GetEffectiveTld(dm *dnsutils.DnsMessage) int {
	// PublicSuffix is case sensitive.
	// remove ending dot ?
	qname := strings.ToLower(dm.DNS.Qname)
	qname = strings.TrimSuffix(qname, ".")

	// search
	etld, icann := publicsuffixlist.PublicSuffix(qname)
	if icann {
		dm.PublicSuffix.QnamePublicSuffix = etld
	} else {
		p.LogError("ICANN Unmanaged")
	}
	return RETURN_SUCCESS
}

func (p *NormalizeProcessor) GetEffectiveTldPlusOne(dm *dnsutils.DnsMessage) int {
	// PublicSuffix is case sensitive, remove ending dot ?
	qname := strings.ToLower(dm.DNS.Qname)
	qname = strings.TrimSuffix(qname, ".")

	if etld, err := publicsuffixlist.EffectiveTLDPlusOne(qname); err == nil {
		dm.PublicSuffix.QnameEffectiveTLDPlusOne = etld
	}

	return RETURN_SUCCESS
}

func (p *NormalizeProcessor) ProcessDnsMessage(dm *dnsutils.DnsMessage) int {
	if len(p.activeProcessors) == 0 {
		return RETURN_SUCCESS
	}

	var r_code int
	for _, fn := range p.activeProcessors {
		r_code = fn(dm)
		if r_code != RETURN_SUCCESS {
			return r_code
		}
	}

	return RETURN_SUCCESS
}
