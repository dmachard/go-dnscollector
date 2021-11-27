package dnsutils

import (
	"bytes"
	"log"
	"strconv"
	"strings"
)

type DnsAnswer struct {
	Name      string `json:"name" msgpack:"name"`
	Rdatatype string `json:"rdatatype" msgpack:"rdatatype"`
	Class     int    `json:"-" msgpack:"-"`
	Ttl       int    `json:"ttl" msgpack:"ttl"`
	Rdata     string `json:"rdata" msgpack:"rdata"`
}

type DnsMessage struct {
	Operation        string      `json:"operation" msgpack:"operation"`
	Identity         string      `json:"identity" msgpack:"identity"`
	Family           string      `json:"family" msgpack:"family"`
	Protocol         string      `json:"protocol" msgpack:"protocol"`
	QueryIp          string      `json:"query-ip" msgpack:"query-ip"`
	QueryPort        string      `json:"query-port" msgpack:"query-port"`
	ResponseIp       string      `json:"response-ip" msgpack:"response-ip"`
	ResponsePort     string      `json:"response-port" msgpack:"response-port"`
	Type             string      `json:"-" msgpack:"-"`
	Payload          []byte      `json:"-" msgpack:"-"`
	Length           int         `json:"length" msgpack:"-"`
	Id               int         `json:"-" msgpack:"-"`
	Rcode            string      `json:"rcode" msgpack:"rcode"`
	Qname            string      `json:"qname" msgpack:"qname"`
	Qtype            string      `json:"qtype" msgpack:"qtype"`
	Latency          float64     `json:"-" msgpack:"-"`
	LatencySec       string      `json:"latency" msgpack:"latency"`
	TimestampRFC3339 string      `json:"timestamp-rfc3339" msgpack:"timestamp-rfc3339"`
	Timestamp        float64     `json:"-" msgpack:"-"`
	TimeSec          int         `json:"-" msgpack:"-"`
	TimeNsec         int         `json:"-" msgpack:"-"`
	Answers          []DnsAnswer `json:"answers" msgpack:"answers"`
	CountryIsoCode   string      `json:"country-isocode" msgpack:"country-isocode"`
}

func (dm *DnsMessage) Init() {
	dm.Operation, dm.Type = "-", "-"
	dm.Identity = "-"
	dm.Family, dm.Protocol = "-", "-"
	dm.QueryIp, dm.QueryPort = "-", "-"
	dm.ResponseIp, dm.ResponsePort = "-", "-"
	dm.Rcode, dm.Qtype = "-", "-"
	dm.Qname, dm.LatencySec = "-", "-"
	dm.TimestampRFC3339 = "-"
	dm.CountryIsoCode = "-"
}

func (dm *DnsMessage) Bytes(format []string) []byte {
	var s bytes.Buffer

	for i, word := range format {
		switch word {
		case "ttl":
			if len(dm.Answers) > 0 {
				s.WriteString(strconv.Itoa(dm.Answers[0].Ttl))
			} else {
				s.WriteString("-")
			}
		case "answer":
			if len(dm.Answers) > 0 {
				s.WriteString(dm.Answers[0].Rdata)
			} else {
				s.WriteString("-")
			}
		case "answercount":
			s.WriteString(strconv.Itoa(len(dm.Answers)))
		case "id":
			s.WriteString(strconv.Itoa(dm.Id))
		case "qr":
			s.WriteString(strings.ToUpper(dm.Type))
		case "timestamp":
			s.WriteString(dm.TimestampRFC3339)
		case "identity":
			s.WriteString(dm.Identity)
		case "operation":
			s.WriteString(dm.Operation)
		case "rcode":
			s.WriteString(dm.Rcode)
		case "queryip":
			s.WriteString(dm.QueryIp)
		case "queryport":
			s.WriteString(dm.QueryPort)
		case "responseip":
			s.WriteString(dm.ResponseIp)
		case "responseport":
			s.WriteString(dm.ResponsePort)
		case "family":
			s.WriteString(dm.Family)
		case "protocol":
			s.WriteString(dm.Protocol)
		case "length":
			s.WriteString(strconv.Itoa(dm.Length) + "b")
		case "qname":
			s.WriteString(dm.Qname)
		case "qtype":
			s.WriteString(dm.Qtype)
		case "latency":
			s.WriteString(dm.LatencySec)
		case "country":
			s.WriteString(dm.CountryIsoCode)
		default:
			log.Fatalf("unsupport directive for text format: %s", word)
		}

		if i < len(format)-1 {
			s.WriteString(" ")
		}
	}

	s.WriteString("\n")

	return s.Bytes()
}

func (dm *DnsMessage) String(format []string) string {
	return string(dm.Bytes(format))
}

func GetFakeDnsMessage() DnsMessage {
	dm := DnsMessage{}
	dm.Init()
	dm.Identity = "collector"
	dm.Operation = "CLIENT_QUERY"
	dm.Type = "query"
	dm.Qname = "dns.collector"
	dm.QueryIp = "1.2.3.4"
	dm.QueryPort = "1234"
	dm.ResponseIp = "4.3.2.1"
	dm.ResponsePort = "4321"
	dm.Rcode = "NOERROR"
	dm.Qtype = "A"
	return dm
}
