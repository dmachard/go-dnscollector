package processors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/miekg/dns"
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

func GetFakeDns() ([]byte, error) {
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dns.collector.", dns.TypeA)
	return dnsmsg.Pack()
}

type DnsProcessor struct {
	done      chan bool
	recv_from chan dnsutils.DnsMessage
	logger    *logger.Logger
}

func NewDnsProcessor(logger *logger.Logger) DnsProcessor {
	logger.Info("dns processor - initialization...")
	d := DnsProcessor{
		done:      make(chan bool),
		recv_from: make(chan dnsutils.DnsMessage, 512),
		logger:    logger,
	}
	logger.Info("dns processor - ready")
	return d
}

func (d *DnsProcessor) GetChannel() chan dnsutils.DnsMessage {
	return d.recv_from
}

func (d *DnsProcessor) GetChannelList() []chan dnsutils.DnsMessage {
	channel := []chan dnsutils.DnsMessage{}
	channel = append(channel, d.recv_from)
	return channel
}

func (d *DnsProcessor) Stop() {
	close(d.recv_from)

	// read done channel and block until run is terminated
	<-d.done
	close(d.done)
}

func (d *DnsProcessor) Run(send_to []chan dnsutils.DnsMessage) {
	d.logger.Info("dns processor - running...")

	cache_ttl := dnsutils.NewCacheDns(10 * time.Second)

	for dm := range d.recv_from {
		// compute timestamp
		dm.Timestamp = float64(dm.TimeSec) + float64(dm.TimeNsec)/1e9
		ts := time.Unix(int64(dm.TimeSec), int64(dm.TimeNsec))
		dm.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

		// decode the dns payload
		dns_id, dns_qr, dns_rcode, dns_qdcount, dns_ancount, err := DecodeDns(dm.Payload)
		//fmt.Println(dns_id, dns_qr, dns_rcode, dns_qdcount, dns_ancount)
		if err != nil {
			d.logger.Error("dns parser packet error: %s - %v+", err, dm)
			continue
		}

		// dns reply ?
		if dns_qr == 1 {
			dm.Operation = "CLIENT_RESPONSE"
			dm.Type = "reply"
			qip := dm.QueryIp
			qport := dm.QueryPort
			dm.QueryIp = dm.ResponseIp
			dm.QueryPort = dm.ResponsePort
			dm.ResponseIp = qip
			dm.ResponsePort = qport
		} else {
			dm.Type = "query"
			dm.Operation = "CLIENT_QUERY"
		}

		dm.Id = dns_id
		dm.Rcode = RcodeToString(dns_rcode)

		// continue to decode the dns payload to extract the qname and rrtype
		var dns_offsetrr int
		if dns_qdcount > 0 {
			dns_qname, dns_rrtype, offsetrr, err := DecodeQuestion(dm.Payload)
			if err != nil {
				d.logger.Error("dns parser question error: %s - %v+", err, dm)
				continue
			}
			dm.Qname = dns_qname
			dm.Qtype = RdatatypeToString(dns_rrtype)
			dns_offsetrr = offsetrr
		}

		// decode dns answers
		if dns_ancount > 0 {
			dm.Answers, err = DecodeAnswer(dns_ancount, dns_offsetrr, dm.Payload)
			if err != nil {
				d.logger.Error("dns parser answer error: %s - %v+", err, dm)
				continue
			}
		}

		// compute latency if possible
		queryport, _ := strconv.Atoi(dm.QueryPort)
		if len(dm.QueryIp) > 0 && queryport > 0 {
			// compute the hash of the query
			hash_data := []string{dm.QueryIp, dm.QueryPort, strconv.Itoa(dm.Id)}

			hashfnv := fnv.New64a()
			hashfnv.Write([]byte(strings.Join(hash_data[:], "+")))

			if dm.Type == "query" {
				cache_ttl.Set(hashfnv.Sum64(), dm.Timestamp)
			} else {
				value, ok := cache_ttl.Get(hashfnv.Sum64())
				if ok {
					dm.Latency = dm.Timestamp - value
				}
			}
		}

		// convert latency to human
		dm.LatencySec = fmt.Sprintf("%.6f", dm.Latency)

		for i := range send_to {
			send_to[i] <- dm
		}
	}

	// dnstap channel consumer closed
	d.done <- true
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

func DecodeDns(payload []byte) (int, int, int, int, int, error) {
	if len(payload) < DnsLen {
		return 0, 0, 0, 0, 0, errors.New("dns payload too short to decode header")
	}
	// decode ID
	id := binary.BigEndian.Uint16(payload[:2])
	// decode QR
	qr := binary.BigEndian.Uint16(payload[2:4]) >> 15
	// decode RCODE
	rcode := binary.BigEndian.Uint16(payload[2:4]) & 15
	// decode QDCOUNT
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	// decode ANCOUNT
	ancount := binary.BigEndian.Uint16(payload[6:8])
	return int(id), int(qr), int(rcode), int(qdcount), int(ancount), nil
}

/*
	DNS QUESTION
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
func DecodeQuestion(payload []byte) (string, int, int, error) {
	// Decode QNAME
	qname, offset, err := ParseLabels(DnsLen, payload)
	if err != nil {
		return "", 0, 0, err
	}

	// decode QTYPE and support invalid packet, some abuser sends it...
	var qtype uint16
	if len(payload[offset:]) < 4 {
		qtype = 0
		offset += len(payload[offset:])
	} else {
		qtype = binary.BigEndian.Uint16(payload[offset : offset+2])
		offset += 4
	}
	return qname, int(qtype), offset, err
}

/*
    DNS ANSWER
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

	PTR can be used on NAME for compression
									1  1  1  1  1  1
	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	| 1  1|                OFFSET                   |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func DecodeAnswer(ancount int, start_offset int, payload []byte) ([]dnsutils.DnsAnswer, error) {
	offset := start_offset
	answers := []dnsutils.DnsAnswer{}
	for i := 0; i < ancount; i++ {
		// Decode NAME
		name, offset_next, err := ParseLabels(offset, payload)
		if err != nil {
			return answers, err
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
		rdata := payload[offset_next+10 : offset_next+10+int(rdlength)]

		// parse rdata
		rdatatype := RdatatypeToString(int(t))
		parsed := ParseRdata(rdatatype, rdata)

		// append answer
		a := dnsutils.DnsAnswer{
			Name:      name,
			Rdatatype: rdatatype,
			Class:     int(class),
			Ttl:       int(ttl),
			Rdata:     parsed,
		}
		answers = append(answers, a)

		offset = offset_next + 10 + int(rdlength)
	}
	return answers, nil
}

func ParseLabels(offset int, payload []byte) (string, int, error) {
	labels := []string{}
	for {
		if offset >= len(payload) {
			return "", 0, errors.New("dns payload too short to decode labels")
		}

		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}
		// label pointer support ?
		if length>>6 == 3 {
			ptr := binary.BigEndian.Uint16(payload[offset:offset+2]) & 16383
			label, _, _ := ParseLabels(int(ptr), payload)
			labels = append(labels, label)
			offset += 2
			break

		} else {
			label := payload[offset+1 : offset+length+1]
			labels = append(labels, string(label))

			offset += length + 1
		}
	}
	return strings.Join(labels[:], "."), offset, nil
}

func ParseRdata(rdatatype string, rdata []byte) string {
	switch rdatatype {
	case "A":
		return ParseA(rdata)
	case "AAAA":
		return ParseAAAA(rdata)
	default:
		return "-"
	}
}

/*
    IPv4
	                               1  1  1  1  1  1
	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ADDRESS                    |
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
func ParseA(r []byte) string {
	var ip []string
	for i := 0; i < len(r); i++ {
		ip = append(ip, strconv.Itoa(int(r[i])))
	}
	return strings.Join(ip, ".")
}

/*
    IPv6
	                               1  1  1  1  1  1
	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
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
func ParseAAAA(rdata []byte) string {
	var ip []string
	for i := 0; i < len(rdata); i += 2 {
		ip = append(ip, fmt.Sprintf("%x", binary.BigEndian.Uint16(rdata[i:i+2])))
	}
	return strings.Join(ip, ":")
}
