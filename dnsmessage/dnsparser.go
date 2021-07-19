package dnsmessage

import (
	"encoding/binary"
	"errors"
	"strings"
)

const DnsLen = 12

var (
	Rdatatypes = map[int]string{
		0:     "NONE",
		1:     "A",
		2:     "NS",
		3:     "MD",
		4:     "MF",
		5:     "CNAME",
		6:     "SOA",
		7:     "MB",
		8:     "MG",
		9:     "MR",
		10:    "NULL",
		11:    "WKS",
		12:    "PTR",
		13:    "HINFO",
		14:    "MINFO",
		15:    "MX",
		16:    "TXT",
		17:    "RP",
		18:    "AFSDB",
		19:    "X25",
		20:    "ISDN",
		21:    "RT",
		22:    "NSAP",
		23:    "NSAP_PTR",
		24:    "SIG",
		25:    "KEY",
		26:    "PX",
		27:    "GPOS",
		28:    "AAAA",
		29:    "LOC",
		30:    "NXT",
		33:    "SRV",
		35:    "NAPTR",
		36:    "KX",
		37:    "CERT",
		38:    "A6",
		39:    "DNAME",
		41:    "OPT",
		42:    "APL",
		43:    "DS",
		44:    "SSHFP",
		45:    "IPSECKEY",
		46:    "RRSIG",
		47:    "NSEC",
		48:    "DNSKEY",
		49:    "DHCID",
		50:    "NSEC3",
		51:    "NSEC3PARAM",
		52:    "TSLA",
		53:    "SMIMEA",
		55:    "HIP",
		56:    "NINFO",
		59:    "CDS",
		60:    "CDNSKEY",
		61:    "OPENPGPKEY",
		62:    "CSYNC",
		64:    "SVCB",
		65:    "HTTPS",
		99:    "SPF",
		103:   "UNSPEC",
		108:   "EUI48",
		109:   "EUI64",
		249:   "TKEY",
		250:   "TSIG",
		251:   "IXFR",
		252:   "AXFR",
		253:   "MAILB",
		254:   "MAILA",
		255:   "ANY",
		256:   "URI",
		257:   "CAA",
		258:   "AVC",
		259:   "AMTRELAY",
		32768: "TA",
		32769: "DLV",
	}
	Rcodes = map[int]string{
		0:  "NOERROR",
		1:  "FORMERR",
		2:  "SERVFAIL",
		3:  "NXDOMAIN",
		4:  "NOIMP",
		5:  "REFUSED",
		6:  "YXDOMAIN",
		7:  "YXRRSET",
		8:  "NXRRSET",
		9:  "NOTAUTH",
		10: "NOTZONE",
		11: "DSOTYPENI",
		16: "BADSIG",
		17: "BADKEY",
		18: "BADTIME",
		19: "BADMODE",
		20: "BADNAME",
		21: "BADALG",
		22: "BADTRUNC",
		23: "BADCOOKIE",
	}
)

func RdatatypeToString(rrtype int) string {
	if value, ok := Rdatatypes[rrtype]; ok {
		return value
	}
	return "-"
}

func RcodeToString(rcode int) string {
	if value, ok := Rcodes[rcode]; ok {
		return value
	}
	return "-"
}

func DecodeDns(payload []byte) (int, int, int, error) {
	if len(payload) < DnsLen {
		return 0, 0, 0, errors.New("dns message too short")
	}
	id := binary.BigEndian.Uint16(payload[:2])
	rcode := binary.BigEndian.Uint16(payload[2:4]) & 15
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	return int(id), int(rcode), int(qdcount), nil
}

func DecodeQuestion(payload []byte) (string, int) {
	dns_rr := payload[DnsLen:]
	qname := []string{}
	for len(dns_rr) > 0 {
		length := dns_rr[0]
		if length == 0 {
			break
		}

		label := dns_rr[1 : length+1]
		qname = append(qname, string(label))

		dns_rr = dns_rr[length+1:]
	}
	var qtype uint16
	// condition to handle invalid packet, some abuser sends it...
	if len(dns_rr) <= 4 {
		qtype = 0
	} else {
		qtype = binary.BigEndian.Uint16(dns_rr[1:3])
	}
	return strings.Join(qname[:], "."), int(qtype)
}
