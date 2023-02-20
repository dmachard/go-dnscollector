package transformers

import (
	"errors"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
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
	config *dnsutils.ConfigTransformers
}

func NewNormalizeSubprocessor(config *dnsutils.ConfigTransformers) NormalizeProcessor {
	s := NormalizeProcessor{
		config: config,
	}

	return s
}

func (s *NormalizeProcessor) IsEnabled() bool {
	return s.config.Normalize.Enable
}

func (s *NormalizeProcessor) Lowercase(qname string) string {
	return strings.ToLower(qname)
}

func (p *NormalizeProcessor) InitDnsMessage(dm *dnsutils.DnsMessage) {
	dm.PublicSuffix = &dnsutils.PublicSuffix{
		QnamePublicSuffix:        "-",
		QnameEffectiveTLDPlusOne: "-",
	}
}

func (s *NormalizeProcessor) QuietText(dm *dnsutils.DnsMessage) {
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
}

func (s *NormalizeProcessor) GetEffectiveTld(qname string) (string, error) {

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

func (s *NormalizeProcessor) GetEffectiveTldPlusOne(qname string) (string, error) {
	// PublicSuffix is case sensitive.
	// remove ending dot ?
	qname = strings.ToLower(qname)
	qname = strings.TrimSuffix(qname, ".")

	return publicsuffixlist.EffectiveTLDPlusOne(qname)
}
