package transformers

import (
	"fmt"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
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
	DNSQr = map[string]string{
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
	config           *pkgconfig.ConfigTransformers
	logger           *logger.Logger
	name             string
	instance         int
	activeProcessors []func(dm *dnsutils.DNSMessage) int
	outChannels      []chan dnsutils.DNSMessage
	LogInfo          func(msg string, v ...interface{})
	LogError         func(msg string, v ...interface{})
}

func NewNormalizeTransform(
	config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage) NormalizeProcessor {
	s := NormalizeProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		instance:    instance,
		outChannels: outChannels,
	}

	s.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - normalize - ", name, instance)
		logger.Info(log+msg, v...)
	}

	s.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - normalize - ", name, instance)
		logger.Error(log+msg, v...)
	}

	return s
}

func (p *NormalizeProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config
}

func (p *NormalizeProcessor) LoadActiveProcessors() {
	// clean the slice
	p.activeProcessors = p.activeProcessors[:0]

	if p.config.Normalize.RRLowerCase {
		p.activeProcessors = append(p.activeProcessors, p.RRLowercase)
		p.LogInfo("processor=lowercase is enabled")
	}

	if p.config.Normalize.QnameLowerCase {
		p.activeProcessors = append(p.activeProcessors, p.QnameLowercase)
		p.LogInfo("processor=lowercase is enabled")
	}

	if p.config.Normalize.QuietText {
		p.activeProcessors = append(p.activeProcessors, p.QuietText)
		p.LogInfo("processor=quiet_text is enabled")
	}

	if p.config.Normalize.AddTld {
		p.activeProcessors = append(p.activeProcessors, p.GetEffectiveTld)
		p.LogInfo("processor=add_tld is enabled")
	}
	if p.config.Normalize.AddTldPlusOne {
		p.activeProcessors = append(p.activeProcessors, p.GetEffectiveTldPlusOne)
		p.LogInfo("add tld+1 subprocessor enabled")
	}
}

func (p *NormalizeProcessor) IsEnabled() bool {
	return p.config.Normalize.Enable
}

func (p *NormalizeProcessor) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.PublicSuffix == nil {
		dm.PublicSuffix = &dnsutils.TransformPublicSuffix{
			QnamePublicSuffix:        "-",
			QnameEffectiveTLDPlusOne: "-",
			ManagedByICANN:           false,
		}
	}
}

func (p *NormalizeProcessor) QnameLowercase(dm *dnsutils.DNSMessage) int {
	dm.DNS.Qname = strings.ToLower(dm.DNS.Qname)

	return ReturnSuccess
}

func processRecords(records []dnsutils.DNSAnswer) {
	for i := range records {
		records[i].Name = strings.ToLower(records[i].Name)
		switch records[i].Rdatatype {
		case "CNAME", "SOA", "NS", "MX", "PTR", "SRV":
			records[i].Rdata = strings.ToLower(records[i].Rdata)
		}
	}
}

func (p *NormalizeProcessor) RRLowercase(dm *dnsutils.DNSMessage) int {
	processRecords(dm.DNS.DNSRRs.Answers)
	processRecords(dm.DNS.DNSRRs.Nameservers)
	processRecords(dm.DNS.DNSRRs.Records)
	return ReturnSuccess
}

func (p *NormalizeProcessor) QuietText(dm *dnsutils.DNSMessage) int {
	if v, found := DnstapMessage[dm.DNSTap.Operation]; found {
		dm.DNSTap.Operation = v
	}
	if v, found := DNSQr[dm.DNS.Type]; found {
		dm.DNS.Type = v
	}
	if v, found := IPversion[dm.NetworkInfo.Family]; found {
		dm.NetworkInfo.Family = v
	}
	if v, found := Rcodes[dm.DNS.Rcode]; found {
		dm.DNS.Rcode = v
	}
	return ReturnSuccess
}

func (p *NormalizeProcessor) GetEffectiveTld(dm *dnsutils.DNSMessage) int {
	// PublicSuffix is case sensitive.
	// remove ending dot ?
	qname := strings.ToLower(dm.DNS.Qname)
	qname = strings.TrimSuffix(qname, ".")

	// search
	etld, icann := publicsuffixlist.PublicSuffix(qname)
	if icann {
		dm.PublicSuffix.QnamePublicSuffix = etld
		dm.PublicSuffix.ManagedByICANN = true
	} else {
		dm.PublicSuffix.ManagedByICANN = false
	}
	return ReturnSuccess
}

func (p *NormalizeProcessor) GetEffectiveTldPlusOne(dm *dnsutils.DNSMessage) int {
	// PublicSuffix is case sensitive, remove ending dot ?
	qname := strings.ToLower(dm.DNS.Qname)
	qname = strings.TrimSuffix(qname, ".")

	if etld, err := publicsuffixlist.EffectiveTLDPlusOne(qname); err == nil {
		dm.PublicSuffix.QnameEffectiveTLDPlusOne = etld
	}

	return ReturnSuccess
}

func (p *NormalizeProcessor) ProcessDNSMessage(dm *dnsutils.DNSMessage) int {
	if len(p.activeProcessors) == 0 {
		return ReturnSuccess
	}

	var rCode int
	for _, fn := range p.activeProcessors {
		rCode = fn(dm)
		if rCode != ReturnSuccess {
			return rCode
		}
	}

	return ReturnSuccess
}
