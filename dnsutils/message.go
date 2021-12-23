package dnsutils

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

type DnsAnswer struct {
	Name      string `json:"name" msgpack:"name"`
	Rdatatype string `json:"rdatatype" msgpack:"rdatatype"`
	Class     int    `json:"-" msgpack:"-"`
	Ttl       int    `json:"ttl" msgpack:"ttl"`
	Rdata     string `json:"rdata" msgpack:"rdata"`
}

type DnsMessage struct {
	Operation              string      `json:"operation" msgpack:"operation"`
	Identity               string      `json:"identity" msgpack:"identity"`
	Family                 string      `json:"family" msgpack:"family"`
	Protocol               string      `json:"protocol" msgpack:"protocol"`
	QueryIp                string      `json:"query-ip" msgpack:"query-ip"`
	QueryPort              string      `json:"query-port" msgpack:"query-port"`
	ResponseIp             string      `json:"response-ip" msgpack:"response-ip"`
	ResponsePort           string      `json:"response-port" msgpack:"response-port"`
	Type                   string      `json:"-" msgpack:"-"`
	Payload                []byte      `json:"-" msgpack:"-"`
	Length                 int         `json:"length" msgpack:"-"`
	Id                     int         `json:"-" msgpack:"-"`
	Rcode                  string      `json:"rcode" msgpack:"rcode"`
	Qname                  string      `json:"qname" msgpack:"qname"`
	Qtype                  string      `json:"qtype" msgpack:"qtype"`
	Latency                float64     `json:"-" msgpack:"-"`
	LatencySec             string      `json:"latency" msgpack:"latency"`
	TimestampRFC3339       string      `json:"timestamp-rfc3339ns" msgpack:"timestamp-rfc3339ns"`
	Timestamp              float64     `json:"-" msgpack:"-"`
	TimeSec                int         `json:"-" msgpack:"-"`
	TimeNsec               int         `json:"-" msgpack:"-"`
	Answers                []DnsAnswer `json:"answers" msgpack:"answers"`
	Nameservers            []DnsAnswer `json:"nameservers" msgpack:"nameservers"`
	CountryIsoCode         string      `json:"country-isocode" msgpack:"country-isocode"`
	AutonomousSystemNumber string      `json:"as-number" msgpack:"as-number"`
	AutonomousSystemOrg    string      `json:"as-owner" msgpack:"as-owner"`
	City                   string      `json:"city" msgpack:"city"`
	Continent              string      `json:"continent" msgpack:"continent"`
	MalformedPacket        int         `json:"malformed-packet" msgpack:"malformed-packet"`
	Truncated              string      `json:"flag-tc" msgpack:"flag-tc"`
	AuthoritativeAnswer    string      `json:"flag-aa" msgpack:"flag-aa"`
	RecursionAvailable     string      `json:"flag-ra" msgpack:"flag-ra"`
	AuthenticData          string      `json:"flag-ad" msgpack:"flag-ad"`
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

	dm.MalformedPacket = 0
	dm.Truncated = "-"
	dm.AuthoritativeAnswer = "-"
	dm.RecursionAvailable = "-"
	dm.AuthenticData = "-"

	dm.CountryIsoCode = "-"
	dm.AutonomousSystemNumber = "-"
	dm.AutonomousSystemOrg = "-"
	dm.City = "-"
	dm.Continent = "-"
}

func (dm *DnsMessage) Bytes(format []string, delimiter string) []byte {
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
			s.WriteString(strings.ToUpper(dm.Type[:1]))
		case "timestamp": // keep it just for backward compatibility
			s.WriteString(dm.TimestampRFC3339)
		case "timestamp-rfc3339ns":
			s.WriteString(dm.TimestampRFC3339)
		case "timestamp-unixms":
			s.WriteString(fmt.Sprintf("%.3f", dm.Timestamp))
		case "timestamp-unixus":
			s.WriteString(fmt.Sprintf("%.6f", dm.Timestamp))
		case "timestamp-unixns":
			s.WriteString(fmt.Sprintf("%.9f", dm.Timestamp))
		case "localtime":
			ts := time.Unix(int64(dm.TimeSec), int64(dm.TimeNsec))
			s.WriteString(ts.Format("2006-01-02 15:04:05.999999999"))
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
		case "continent":
			s.WriteString(dm.Continent)
		case "country":
			s.WriteString(dm.CountryIsoCode)
		case "city":
			s.WriteString(dm.City)
		case "as-number":
			s.WriteString(dm.AutonomousSystemNumber)
		case "as-owner":
			s.WriteString(dm.AutonomousSystemOrg)
		case "malformed":
			s.WriteString(strconv.Itoa(dm.MalformedPacket))
		case "tc":
			s.WriteString(dm.Truncated)
		case "aa":
			s.WriteString(dm.AuthoritativeAnswer)
		case "ra":
			s.WriteString(dm.RecursionAvailable)
		case "ad":
			s.WriteString(dm.AuthenticData)
		default:
			log.Fatalf("unsupport directive for text format: %s", word)
		}

		if i < len(format)-1 {
			s.WriteString(" ")
		}
	}

	s.WriteString(delimiter)

	return s.Bytes()
}

func (dm *DnsMessage) String(format []string) string {
	delimiter := "\n"
	return string(dm.Bytes(format, delimiter))
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
