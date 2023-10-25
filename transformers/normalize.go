package transformers

import (
	"fmt"
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
	instance         int
	activeProcessors []func(dm *dnsutils.DnsMessage) int
	outChannels      []chan dnsutils.DnsMessage
	logInfo          func(msg string, v ...interface{})
	logError         func(msg string, v ...interface{})
}

func NewNormalizeSubprocessor(
	config *dnsutils.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DnsMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{}),
) NormalizeProcessor {
	s := NormalizeProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		instance:    instance,
		outChannels: outChannels,
		logInfo:     logInfo,
		logError:    logError,
	}

	s.LoadActiveProcessors()
	return s
}

func (p *NormalizeProcessor) ReloadConfig(config *dnsutils.ConfigTransformers) {
	// save the new config
	p.config = config
	p.LoadActiveProcessors()
}

func (p *NormalizeProcessor) LogInfo(msg string, v ...interface{}) {
	log := fmt.Sprintf("transformer=normalize#%d - ", p.instance)
	p.logInfo(log+msg, v...)
}

func (p *NormalizeProcessor) LogError(msg string, v ...interface{}) {
	p.logError("transformer=normalize - "+msg, v...)
}

func (p *NormalizeProcessor) LoadActiveProcessors() {
	// clean the slice
	p.activeProcessors = p.activeProcessors[:0]

	if p.config.Normalize.QnameLowerCase {
		p.activeProcessors = append(p.activeProcessors, p.LowercaseQname)
		p.LogInfo("lowercase subprocessor is enabled")
	}

	if p.config.Normalize.QuietText {
		p.activeProcessors = append(p.activeProcessors, p.QuietText)
		p.LogInfo("quiet text subprocessor is enabled")
	}

	if p.config.Normalize.AddTld {
		p.activeProcessors = append(p.activeProcessors, p.GetEffectiveTld)
		p.LogInfo("add tld subprocessor is enabled")
	}
	if p.config.Normalize.AddTldPlusOne {
		p.activeProcessors = append(p.activeProcessors, p.GetEffectiveTldPlusOne)
		p.LogInfo("add tld+1 subprocessor enabled")
	}
}

func (s *NormalizeProcessor) IsEnabled() bool {
	return s.config.Normalize.Enable
}

func (p *NormalizeProcessor) InitDnsMessage(dm *dnsutils.DnsMessage) {
	if dm.PublicSuffix == nil {
		dm.PublicSuffix = &dnsutils.TransformPublicSuffix{
			QnamePublicSuffix:        "-",
			QnameEffectiveTLDPlusOne: "-",
		}
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
		p.logError("suffix unmanaged by icann: %s", qname)
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
