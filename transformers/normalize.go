package transformers

import (
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	publicsuffixlist "golang.org/x/net/publicsuffix"
)

var (
	DnstapMessage = map[string]string{
		"AUTH_QUERY": "AQ", "AUTH_RESPONSE": "AR",
		"RESOLVER_QUERY": "RQ", "RESOLVER_RESPONSE": "RR",
		"CLIENT_QUERY": "CQ", "CLIENT_RESPONSE": "CR",
		"FORWARDER_QUERY": "FQ", "FORWARDER_RESPONSE": "FR",
		"STUB_QUERY": "SQ", "STUB_RESPONSE": "SR",
		"TOOL_QUERY": "TQ", "TOOL_RESPONSE": "TR",
		"UPDATE_QUERY": "UQ", "UPDATE_RESPONSE": "UR",
		"DNSQueryType": "Q", "DNSResponseType": "R", // powerdns
	}
	DNSQr = map[string]string{
		"QUERY": "Q", "REPLY": "R",
	}

	IPversion = map[string]string{
		"INET6": "6", "INET": "4",
	}

	Rcodes = map[string]string{
		"NOERROR": "0", "FORMERR": "1", "SERVFAIL": "2", "NXDOMAIN": "3", "NOIMP": "4", "REFUSED": "5", "YXDOMAIN": "6",
		"YXRRSET": "7", "NXRRSET": "8", "NOTAUTH": "9", "NOTZONE": "10", "DSOTYPENI": "11",
		"BADSIG": "16", "BADKEY": "17", "BADTIME": "18", "BADMODE": "19", "BADNAME": "20", "BADALG": "21", "BADTRUNC": "22", "BADCOOKIE": "23",
	}
)

func processRecords(records []dnsutils.DNSAnswer) {
	for i := range records {
		records[i].Name = strings.ToLower(records[i].Name)
		switch records[i].Rdatatype {
		case "CNAME", "SOA", "NS", "MX", "PTR", "SRV":
			records[i].Rdata = strings.ToLower(records[i].Rdata)
		}
	}
}

type NormalizeTransform struct {
	GenericTransformer
}

func NewNormalizeTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *NormalizeTransform {
	t := &NormalizeTransform{GenericTransformer: NewTransformer(config, logger, "normalize", name, instance, nextWorkers)}
	return t
}

func (t *NormalizeTransform) GetTransforms() ([]Subtransform, error) {
	subprocessors := []Subtransform{}
	if t.config.Normalize.RRLowerCase {
		subprocessors = append(subprocessors, Subtransform{name: "normalize:rr-lowercase", processFunc: t.RRLowercase})
	}
	if t.config.Normalize.QnameLowerCase {
		subprocessors = append(subprocessors, Subtransform{name: "normalize:qname-lowercase", processFunc: t.QnameLowercase})
	}
	if t.config.Normalize.QuietText {
		subprocessors = append(subprocessors, Subtransform{name: "normalize:quiet", processFunc: t.QuietText})
	}

	if t.config.Normalize.AddTld {
		subprocessors = append(subprocessors, Subtransform{name: "normalize:add-etld", processFunc: t.GetEffectiveTld})
	}
	if t.config.Normalize.AddTldPlusOne {
		subprocessors = append(subprocessors, Subtransform{name: "normalize:add-etld+1", processFunc: t.GetEffectiveTldPlusOne})
	}
	return subprocessors, nil
}

func (t *NormalizeTransform) QnameLowercase(dm *dnsutils.DNSMessage) (int, error) {
	dm.DNS.Qname = strings.ToLower(dm.DNS.Qname)
	return ReturnKeep, nil
}

func (t *NormalizeTransform) RRLowercase(dm *dnsutils.DNSMessage) (int, error) {
	processRecords(dm.DNS.DNSRRs.Answers)
	processRecords(dm.DNS.DNSRRs.Nameservers)
	processRecords(dm.DNS.DNSRRs.Records)
	return ReturnKeep, nil
}

func (t *NormalizeTransform) QuietText(dm *dnsutils.DNSMessage) (int, error) {
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
	return ReturnKeep, nil
}

func (t *NormalizeTransform) GetEffectiveTld(dm *dnsutils.DNSMessage) (int, error) {
	if dm.PublicSuffix == nil {
		dm.PublicSuffix = &dnsutils.TransformPublicSuffix{
			QnamePublicSuffix: "-", QnameEffectiveTLDPlusOne: "-", ManagedByICANN: false,
		}
	}

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
	return ReturnKeep, nil
}

func (t *NormalizeTransform) GetEffectiveTldPlusOne(dm *dnsutils.DNSMessage) (int, error) {
	if dm.PublicSuffix == nil {
		dm.PublicSuffix = &dnsutils.TransformPublicSuffix{
			QnamePublicSuffix: "-", QnameEffectiveTLDPlusOne: "-", ManagedByICANN: false,
		}
	}

	// PublicSuffix is case sensitive, remove ending dot ?
	qname := strings.ToLower(dm.DNS.Qname)
	qname = strings.TrimSuffix(qname, ".")

	if etld, err := publicsuffixlist.EffectiveTLDPlusOne(qname); err == nil {
		dm.PublicSuffix.QnameEffectiveTLDPlusOne = etld
	}

	return ReturnKeep, nil
}
