package dnsutils

import (
	"bytes"
	"strconv"
)

type DnsAnswer struct {
	Name      string `json:"name"`
	Rdatatype string `json:"rdatatype"`
	Class     int    `json:"-"`
	Ttl       int    `json:"ttl"`
	Rdata     string `json:"rdata"`
}

type DnsMessage struct {
	Operation        string      `json:"operation"`
	Identity         string      `json:"identiy"`
	Family           string      `json:"family"`
	Protocol         string      `json:"protocol"`
	QueryIp          string      `json:"query-ip"`
	QueryPort        string      `json:"query-port"`
	ResponseIp       string      `json:"response-ip"`
	ResponsePort     string      `json:"response-port"`
	Type             string      `json:"-"`
	Payload          []byte      `json:"-"`
	Length           int         `json:"length"`
	Id               int         `json:"-"`
	Rcode            string      `json:"rcode"`
	Qname            string      `json:"qname"`
	Qtype            string      `json:"qtype"`
	Latency          float64     `json:"-"`
	LatencySec       string      `json:"latency"`
	TimestampRFC3339 string      `json:"timestamp-rfc3339"`
	Timestamp        float64     `json:"-"`
	TimeSec          int         `json:"-"`
	TimeNsec         int         `json:"-"`
	Answers          []DnsAnswer `json:"answers"`
	CountryIsoCode   string      `json:"country-isocode"`
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

func (dm *DnsMessage) Bytes() []byte {
	var s bytes.Buffer

	s.WriteString(dm.TimestampRFC3339 + " ")
	s.WriteString(dm.Identity + " ")
	s.WriteString(dm.Operation + " ")
	s.WriteString(dm.Rcode + " ")
	s.WriteString(dm.QueryIp + " ")
	s.WriteString(dm.QueryPort + " ")
	s.WriteString(dm.Family + " ")
	s.WriteString(dm.Protocol + " ")
	s.WriteString(strconv.Itoa(dm.Length) + "b ")
	s.WriteString(dm.Qname + " ")
	s.WriteString(dm.Qtype + " ")
	s.WriteString(dm.LatencySec + "\n")

	return s.Bytes()
}

func (dm *DnsMessage) String() string {
	return string(dm.Bytes())
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
