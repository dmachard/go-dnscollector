package dnsmessage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
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

type answer struct {
	name      string
	rdatatype int
	class     int
	ttl       int
	rdata     string
}

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

/*
	DNS HEADER
									1  1  1  1  1  1
	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      ID                       |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    QDCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ANCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    NSCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ARCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

func DecodeDns(payload []byte) (int, int, int, int, error) {
	if len(payload) < DnsLen {
		return 0, 0, 0, 0, errors.New("dns message too short")
	}
	// decode ID
	id := binary.BigEndian.Uint16(payload[:2])
	// decode RCODE
	rcode := binary.BigEndian.Uint16(payload[2:4]) & 15
	// decode QDCOUNT
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	// decode ANCOUNT
	ancount := binary.BigEndian.Uint16(payload[6:8])
	return int(id), int(rcode), int(qdcount), int(ancount), nil
}

/*
	DNS QUERY
								   1  1  1  1  1  1
	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                     QNAME                     /
	/                                               /
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QTYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QCLASS                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func DecodeQuestion(payload []byte) (string, int, int) {
	fmt.Println("decoding question")
	// Decode QNAME
	qname, offset := ParseLabels(DnsLen, payload)

	// decode QTYPE and support invalid packet, some abuser sends it...
	var qtype uint16
	if len(payload[offset:]) < 4 {
		qtype = 0
		offset += len(payload[offset:])
	} else {
		qtype = binary.BigEndian.Uint16(payload[offset : offset+2])
		offset += 4
	}
	return qname, int(qtype), offset
}

/*
    DNS ANSWERS
	                               1  1  1  1  1  1
	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                                               /
	/                      NAME                     /
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      TYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     CLASS                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      TTL                      |
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                   RDLENGTH                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
	/                     RDATA                     /
	/                                               /
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func DecodeAnswers(ancount int, start_offset int, payload []byte) []answer {
	fmt.Println("decoding answer")
	offset := start_offset
	answers := []answer{}
	for i := 0; i < ancount; i++ {
		// Decode NAME
		name, offset_next := ParseLabels(offset, payload)

		// decode TYPE
		t := binary.BigEndian.Uint16(payload[offset_next : offset_next+2])
		// decode CLASS
		class := binary.BigEndian.Uint16(payload[offset_next+2 : offset_next+4])
		// decode TTL
		ttl := binary.BigEndian.Uint32(payload[offset_next+4 : offset_next+8])
		// decode RDLENGTH
		rdlength := binary.BigEndian.Uint16(payload[offset_next+8 : offset_next+10])
		// decode RDATA
		rdata := payload[offset_next+10 : offset_next+10+int(rdlength)]

		// parse rdata
		parsed := ParseRdata(int(t), rdata)

		// append answer
		a := answer{
			name:      name,
			rdatatype: int(t),
			class:     int(class),
			ttl:       int(ttl),
			rdata:     parsed,
		}
		answers = append(answers, a)

		offset += offset_next + 10 + int(rdlength)
	}
	return answers
}

func ParseLabels(offset int, payload []byte) (string, int) {
	fmt.Printf("decoding label: %d", offset)
	fmt.Print(payload)
	labels := []string{}
	for {
		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}

		if length>>6 == 3 {
			fmt.Println("label compressed!")
			break
		} else {
			label := payload[offset+1 : offset+length+1]
			labels = append(labels, string(label))

			offset += length + 1
		}
	}
	return strings.Join(labels[:], "."), offset
}

func ParseRdata(t int, rdata []byte) string {
	rdatatype := RdatatypeToString(t)
	switch rdatatype {
	case "A":
		return ParseA(rdata)
	case "AAAA":
		return ParseAAAA(rdata)
	default:
		return "..."
	}
}

func ParseA(r []byte) string {
	var ip []string
	for i := 0; i < len(r); i++ {
		ip = append(ip, strconv.Itoa(int(r[i])))
	}
	return strings.Join(ip, ".")
}

func ParseAAAA(rdata []byte) string {
	var ip []string
	for i := 0; i < len(rdata); i += 2 {
		ip = append(ip, fmt.Sprintf("%x", binary.BigEndian.Uint16(rdata[i:i+2])))
	}
	return strings.Join(ip, ":")
}
