package dnsutils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const DnsLen = 12
const UNKNOWN = "UNKNOWN"

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

var ErrDecodeDnsHeaderTooShort = errors.New("malformed pkt, dns payload too short to decode header")
var ErrDecodeDnsLabelTooLong = errors.New("malformed pkt, label too long")
var ErrDecodeDnsLabelInvalidData = errors.New("malformed pkt, invalid label length byte")
var ErrDecodeDnsLabelInvalidOffset = errors.New("malformed pkt, invalid offset to decode label")
var ErrDecodeDnsLabelInvalidPointer = errors.New("malformed pkt, label pointer not pointing to prior data")
var ErrDecodeDnsLabelTooShort = errors.New("malformed pkt, dns payload too short to get label")
var ErrDecodeQuestionQtypeTooShort = errors.New("malformed pkt, not enough data to decode qtype")
var ErrDecodeDnsAnswerTooShort = errors.New("malformed pkt, not enough data to decode answer")
var ErrDecodeDnsAnswerRdataTooShort = errors.New("malformed pkt, not enough data to decode rdata answer")

func RdatatypeToString(rrtype int) string {
	if value, ok := Rdatatypes[rrtype]; ok {
		return value
	}
	return UNKNOWN
}

func RcodeToString(rcode int) string {
	if value, ok := Rcodes[rcode]; ok {
		return value
	}
	return UNKNOWN
}

// error returned if decoding of DNS packet payload fails.
type decodingError struct {
	part string
	err  error
}

func (e *decodingError) Error() string {
	return fmt.Sprintf("malformed %s in DNS packet: %v", e.part, e.err)
}

func (e *decodingError) Unwrap() error {
	return e.err
}

type DnsHeader struct {
	Id      int
	Qr      int
	Opcode  int
	Aa      int
	Tc      int
	Rd      int
	Ra      int
	Z       int
	Ad      int
	Cd      int
	Rcode   int
	Qdcount int
	Ancount int
	Nscount int
	Arcount int
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

func DecodeDns(payload []byte) (DnsHeader, error) {
	dh := DnsHeader{}

	// before to start, check to be sure to have enough data to decode
	if len(payload) < DnsLen {
		return dh, ErrDecodeDnsHeaderTooShort
	}
	// decode ID
	dh.Id = int(binary.BigEndian.Uint16(payload[:2]))

	// decode flags
	dh.Qr = int(binary.BigEndian.Uint16(payload[2:4]) >> 0xF)
	dh.Opcode = int((binary.BigEndian.Uint16(payload[2:4]) >> (3 + 0x8)) & 0xF)
	dh.Aa = int((binary.BigEndian.Uint16(payload[2:4]) >> (2 + 0x8)) & 1)
	dh.Tc = int((binary.BigEndian.Uint16(payload[2:4]) >> (1 + 0x8)) & 1)
	dh.Rd = int((binary.BigEndian.Uint16(payload[2:4]) >> (0x8)) & 1)
	dh.Cd = int((binary.BigEndian.Uint16(payload[2:4]) >> 4) & 1)
	dh.Ad = int((binary.BigEndian.Uint16(payload[2:4]) >> 5) & 1)
	dh.Z = int((binary.BigEndian.Uint16(payload[2:4]) >> 6) & 1)
	dh.Ra = int((binary.BigEndian.Uint16(payload[2:4]) >> 7) & 1)
	dh.Rcode = int(binary.BigEndian.Uint16(payload[2:4]) & 0xF)

	// decode counters
	dh.Qdcount = int(binary.BigEndian.Uint16(payload[4:6]))
	dh.Ancount = int(binary.BigEndian.Uint16(payload[6:8]))
	dh.Nscount = int(binary.BigEndian.Uint16(payload[8:10]))
	dh.Arcount = int(binary.BigEndian.Uint16(payload[10:12]))

	return dh, nil
}

// decodePayload can be used to decode raw payload data in dm.DNS.Payload
// into relevant parts of dm.DNS struct. The payload is decoded according to
// given DNS header.
// If packet is marked as malformed already, this function returs with no
// error, but does not process the packet.
// Error is returned if packet can not be parsed. Returned error wraps the
// original error returned by relevant decoding operation.
func DecodePayload(dm *DnsMessage, header *DnsHeader, config *Config) error {
	if dm.DNS.MalformedPacket {
		// do not continue if packet is malformed, the header can not be
		// trusted.
		return nil
	}

	dm.DNS.Id = header.Id
	dm.DNS.Rcode = RcodeToString(header.Rcode)
	dm.DNS.Opcode = header.Opcode

	// update dnstap operation if the opcode is equal to 5 (dns update)
	if dm.DNS.Opcode == 5 && header.Qr == 1 {
		dm.DnsTap.Operation = "UPDATE_QUERY"
	}
	if dm.DNS.Opcode == 5 && header.Qr == 0 {
		dm.DnsTap.Operation = "UPDATE_RESPONSE"
	}

	if header.Qr == 1 {
		dm.DNS.Flags.QR = true
	}
	if header.Tc == 1 {
		dm.DNS.Flags.TC = true
	}
	if header.Aa == 1 {
		dm.DNS.Flags.AA = true
	}
	if header.Ra == 1 {
		dm.DNS.Flags.RA = true
	}
	if header.Ad == 1 {
		dm.DNS.Flags.AD = true
	}

	var payload_offset int
	// decode DNS question
	if header.Qdcount > 0 {
		dns_qname, dns_rrtype, offsetrr, err := DecodeQuestion(header.Qdcount, dm.DNS.Payload)
		if err != nil {
			dm.DNS.MalformedPacket = true
			return &decodingError{part: "query", err: err}
		}

		dm.DNS.Qname = dns_qname
		dm.DNS.Qtype = RdatatypeToString(dns_rrtype)
		payload_offset = offsetrr
	}

	// decode DNS answers
	if header.Ancount > 0 {
		answers, offset, err := DecodeAnswer(header.Ancount, payload_offset, dm.DNS.Payload)
		if err == nil {
			dm.DNS.DnsRRs.Answers = answers
			payload_offset = offset
		} else if dm.DNS.Flags.TC && (errors.Is(err, ErrDecodeDnsAnswerTooShort) || errors.Is(err, ErrDecodeDnsAnswerRdataTooShort) || errors.Is(err, ErrDecodeDnsLabelTooShort)) {
			dm.DNS.MalformedPacket = true
			dm.DNS.DnsRRs.Answers = answers
			payload_offset = offset
		} else {
			dm.DNS.MalformedPacket = true
			return &decodingError{part: "answer records", err: err}
		}
	}

	// decode authoritative answers
	if header.Nscount > 0 {
		if answers, offsetrr, err := DecodeAnswer(header.Nscount, payload_offset, dm.DNS.Payload); err == nil {
			dm.DNS.DnsRRs.Nameservers = answers
			payload_offset = offsetrr
		} else if dm.DNS.Flags.TC && (errors.Is(err, ErrDecodeDnsAnswerTooShort) || errors.Is(err, ErrDecodeDnsAnswerRdataTooShort) || errors.Is(err, ErrDecodeDnsLabelTooShort)) {
			dm.DNS.MalformedPacket = true
			dm.DNS.DnsRRs.Nameservers = answers
			payload_offset = offsetrr
		} else {
			dm.DNS.MalformedPacket = true
			return &decodingError{part: "authority records", err: err}
		}
	}
	if header.Arcount > 0 {
		// decode additional answers
		answers, _, err := DecodeAnswer(header.Arcount, payload_offset, dm.DNS.Payload)
		if err == nil {
			dm.DNS.DnsRRs.Records = answers
		} else if dm.DNS.Flags.TC && (errors.Is(err, ErrDecodeDnsAnswerTooShort) || errors.Is(err, ErrDecodeDnsAnswerRdataTooShort) || errors.Is(err, ErrDecodeDnsLabelTooShort)) {
			dm.DNS.MalformedPacket = true
			dm.DNS.DnsRRs.Records = answers
		} else {
			dm.DNS.MalformedPacket = true
			return &decodingError{part: "additional records", err: err}
		}
		// decode EDNS options, if there are any
		edns, _, err := DecodeEDNS(header.Arcount, payload_offset, dm.DNS.Payload)
		if err == nil {
			dm.EDNS = edns
		} else if dm.DNS.Flags.TC && (errors.Is(err, ErrDecodeDnsAnswerTooShort) ||
			errors.Is(err, ErrDecodeDnsAnswerRdataTooShort) ||
			errors.Is(err, ErrDecodeDnsLabelTooShort) ||
			errors.Is(err, ErrDecodeEdnsDataTooShort) ||
			errors.Is(err, ErrDecodeEdnsOptionTooShort)) {
			dm.DNS.MalformedPacket = true
			dm.EDNS = edns
		} else {
			dm.DNS.MalformedPacket = true
			return &decodingError{part: "edns options", err: err}
		}
	}
	return nil
}

/*
DNS QUESTION
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
func DecodeQuestion(qdcount int, payload []byte) (string, int, int, error) {
	offset := DnsLen
	var qname string
	var qtype int

	for i := 0; i < qdcount; i++ {
		// the specification allows more than one query in DNS packet,
		// however resolvers rarely support that.
		// If there are more than one query, we will return only the last
		// qname, qtype for now. We will parse them all to allow further
		// processing the packet from right offset.
		var err error
		// Decode QNAME
		qname, offset, err = ParseLabels(offset, payload)
		if err != nil {
			return "", 0, 0, err
		}

		// decode QTYPE and support invalid packet, some abuser sends it...
		if len(payload[offset:]) < 4 {
			return "", 0, 0, ErrDecodeQuestionQtypeTooShort
		} else {
			qtype = int(binary.BigEndian.Uint16(payload[offset : offset+2]))
			offset += 4
		}
	}
	return qname, qtype, offset, nil
}

/*
DNS ANSWER
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

PTR can be used on NAME for compression
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| 1  1|                OFFSET                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

func DecodeAnswer(ancount int, start_offset int, payload []byte) ([]DnsAnswer, int, error) {
	offset := start_offset
	answers := []DnsAnswer{}

	for i := 0; i < ancount; i++ {
		// Decode NAME
		name, offset_next, err := ParseLabels(offset, payload)
		if err != nil {
			return answers, offset, err
		}

		// before to continue, check we have enough data
		if len(payload[offset_next:]) < 10 {
			return answers, offset, ErrDecodeDnsAnswerTooShort
		}
		// decode TYPE
		t := binary.BigEndian.Uint16(payload[offset_next : offset_next+2])
		// decode CLASS
		class := binary.BigEndian.Uint16(payload[offset_next+2 : offset_next+4])
		// decode TTL
		ttl := binary.BigEndian.Uint32(payload[offset_next+4 : offset_next+8])
		// decode RDLENGTH
		rdlength := binary.BigEndian.Uint16(payload[offset_next+8 : offset_next+10])

		// decode RDATA
		// but before to continue, check we have enough data to decode the rdata
		if len(payload[offset_next+10:]) < int(rdlength) {
			return answers, offset, ErrDecodeDnsAnswerRdataTooShort
		}
		rdata := payload[offset_next+10 : offset_next+10+int(rdlength)]

		// ignore OPT, this type is decoded in the EDNS extension
		if t == 41 {
			offset = offset_next + 10 + int(rdlength)
			continue
		}
		// parse rdata
		rdatatype := RdatatypeToString(int(t))
		parsed, err := ParseRdata(rdatatype, rdata, payload[:offset_next+10+int(rdlength)], offset_next+10)
		if err != nil {
			return answers, offset, err
		}

		// finnally append answer to the list
		a := DnsAnswer{
			Name:      name,
			Rdatatype: rdatatype,
			Class:     int(class),
			Ttl:       int(ttl),
			Rdata:     parsed,
		}
		answers = append(answers, a)

		// compute the next offset
		offset = offset_next + 10 + int(rdlength)
	}
	return answers, offset, nil
}

func ParseLabels(offset int, payload []byte) (string, int, error) {
	if offset < 0 {
		return "", 0, ErrDecodeDnsLabelInvalidOffset
	}

	labels := []string{}
	// Where the current decoding run has started. Set after on every pointer jump.
	startOffset := offset
	// Track where the current decoding run is allowed to advance. Set after every pointer jump.
	maxOffset := len(payload)
	// Where the decoded label ends (-1 == uninitialized). Set either on first pointer jump or when the label ends.
	endOffset := -1
	// Keep tabs of the current total length. Ensure that the maximum total name length is 254 (counting
	// separator dots plus one dangling dot).
	totalLength := 0

	for {
		if offset >= len(payload) {
			return "", 0, ErrDecodeDnsLabelTooShort
		} else if offset >= maxOffset {
			return "", 0, ErrDecodeDnsLabelInvalidPointer
		}

		length := int(payload[offset])
		if length == 0 {
			if endOffset == -1 {
				endOffset = offset + 1
			}
			break
		} else if length&0xc0 == 0xc0 {
			if offset+2 > len(payload) {
				return "", 0, ErrDecodeDnsLabelTooShort
			} else if offset+2 > maxOffset {
				return "", 0, ErrDecodeDnsLabelInvalidPointer
			}

			ptr := int(binary.BigEndian.Uint16(payload[offset:offset+2]) & 16383)
			if ptr >= startOffset {
				// Require pointers to always point to prior data (based on a reading of RFC 1035, section 4.1.4).
				return "", 0, ErrDecodeDnsLabelInvalidPointer
			}

			if endOffset == -1 {
				endOffset = offset + 2
			}
			maxOffset = startOffset
			startOffset = ptr
			offset = ptr
		} else if length&0xc0 == 0x00 {
			if offset+length+1 > len(payload) {
				return "", 0, ErrDecodeDnsLabelTooShort
			} else if offset+length+1 > maxOffset {
				return "", 0, ErrDecodeDnsLabelInvalidPointer
			}

			totalLength += length + 1
			if totalLength > 254 {
				return "", 0, ErrDecodeDnsLabelTooLong
			}

			label := payload[offset+1 : offset+length+1]
			labels = append(labels, string(label))
			offset += length + 1
		} else {
			return "", 0, ErrDecodeDnsLabelInvalidData
		}
	}

	return strings.Join(labels[:], "."), endOffset, nil
}

func ParseRdata(rdatatype string, rdata []byte, payload []byte, rdata_offset int) (string, error) {
	var ret string
	var err error
	switch rdatatype {
	case "A":
		ret, err = ParseA(rdata)
	case "AAAA":
		ret, err = ParseAAAA(rdata)
	case "CNAME":
		ret, err = ParseCNAME(rdata_offset, payload)
	case "MX":
		ret, err = ParseMX(rdata_offset, payload)
	case "SRV":
		ret, err = ParseSRV(rdata_offset, payload)
	case "NS":
		ret, err = ParseNS(rdata_offset, payload)
	case "TXT":
		ret, err = ParseTXT(rdata)
	case "PTR":
		ret, err = ParsePTR(rdata_offset, payload)
	case "SOA":
		ret, err = ParseSOA(rdata_offset, payload)
	default:
		ret = "-"
		err = nil
	}
	return ret, err
}

/*
SOA
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     MNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     RNAME                     /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    SERIAL                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    REFRESH                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     RETRY                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    EXPIRE                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    MINIMUM                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseSOA(rdata_offset int, payload []byte) (string, error) {
	var offset int

	primaryNS, offset, err := ParseLabels(rdata_offset, payload)
	if err != nil {
		return "", err
	}

	respMailbox, offset, err := ParseLabels(offset, payload)
	if err != nil {
		return "", err
	}

	// ensure there is enough data to parse rest of the fields
	if offset+20 > len(payload) {
		return "", ErrDecodeDnsAnswerRdataTooShort
	}
	rdata := payload[offset : offset+20]

	serial := binary.BigEndian.Uint32(rdata[0:4])
	refresh := int32(binary.BigEndian.Uint32(rdata[4:8]))
	retry := int32(binary.BigEndian.Uint32(rdata[8:12]))
	expire := int32(binary.BigEndian.Uint32(rdata[12:16]))
	minimum := binary.BigEndian.Uint32(rdata[16:20])

	soa := fmt.Sprintf("%s %s %d %d %d %d %d", primaryNS, respMailbox, serial, refresh, retry, expire, minimum)
	return soa, nil
}

/*
IPv4
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ADDRESS                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseA(r []byte) (string, error) {
	if len(r) < net.IPv4len {
		return "", ErrDecodeDnsAnswerRdataTooShort
	}
	addr := make(net.IP, net.IPv4len)
	copy(addr, r[:net.IPv4len])
	return addr.String(), nil
}

/*
IPv6
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
|                                               |
|                                               |
|                    ADDRESS                    |
|                                               |
|                                               |
|                                               |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseAAAA(rdata []byte) (string, error) {
	if len(rdata) < net.IPv6len {
		return "", ErrDecodeDnsAnswerRdataTooShort
	}
	addr := make(net.IP, net.IPv6len)
	copy(addr, rdata[:net.IPv6len])
	return addr.String(), nil
}

/*
CNAME
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     NAME                      /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseCNAME(rdata_offset int, payload []byte) (string, error) {
	cname, _, err := ParseLabels(rdata_offset, payload)
	if err != nil {
		return "", err
	}
	return cname, err
}

/*
MX
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  PREFERENCE                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                   EXCHANGE                    /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseMX(rdata_offset int, payload []byte) (string, error) {
	// ensure there is enough data for pereference and at least
	// one byte for label
	if len(payload) < rdata_offset+3 {
		return "", ErrDecodeDnsAnswerRdataTooShort
	}
	pref := binary.BigEndian.Uint16(payload[rdata_offset : rdata_offset+2])
	host, _, err := ParseLabels(rdata_offset+2, payload)
	if err != nil {
		return "", err
	}

	mx := fmt.Sprintf("%d %s", pref, host)
	return mx, err
}

/*
SRV
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   PRIORITY                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    WEIGHT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     PORT                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    TARGET                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseSRV(rdata_offset int, payload []byte) (string, error) {
	if len(payload) < rdata_offset+7 {
		return "", ErrDecodeDnsAnswerRdataTooShort
	}
	priority := binary.BigEndian.Uint16(payload[rdata_offset : rdata_offset+2])
	weight := binary.BigEndian.Uint16(payload[rdata_offset+2 : rdata_offset+4])
	port := binary.BigEndian.Uint16(payload[rdata_offset+4 : rdata_offset+6])
	target, _, err := ParseLabels(rdata_offset+6, payload)
	if err != nil {
		return "", err
	}
	srv := fmt.Sprintf("%d %d %d %s", priority, weight, port, target)
	return srv, err
}

/*
NS
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                   NSDNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseNS(rdata_offset int, payload []byte) (string, error) {
	ns, _, err := ParseLabels(rdata_offset, payload)
	if err != nil {
		return "", err
	}
	return ns, err
}

/*
TXT
+--+--+--+--+--+--+--+--+
|         LENGTH        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                   TXT-DATA                    /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseTXT(rdata []byte) (string, error) {
	// ensure there is enough data to read the length
	if len(rdata) < 1 {
		return "", ErrDecodeDnsAnswerRdataTooShort
	}
	length := int(rdata[0])
	if len(rdata)-1 < length {
		return "", ErrDecodeDnsAnswerRdataTooShort
	}
	txt := string(rdata[1 : length+1])
	return txt, nil
}

/*
PTR
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                   PTRDNAME                    /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParsePTR(rdata_offset int, payload []byte) (string, error) {
	ptr, _, err := ParseLabels(rdata_offset, payload)
	if err != nil {
		return "", err
	}
	return ptr, err
}
