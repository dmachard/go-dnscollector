package dnsutils

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"time"
)

var (
	DnsQuery = "QUERY"
	DnsReply = "REPLY"
)

type DnsAnswer struct {
	Name      string `json:"name" msgpack:"name"`
	Rdatatype string `json:"rdatatype" msgpack:"rdatatype"`
	Class     int    `json:"-" msgpack:"-"`
	Ttl       int    `json:"ttl" msgpack:"ttl"`
	Rdata     string `json:"rdata" msgpack:"rdata"`
}

type DnsFlags struct {
	QR bool `json:"qr" msgpack:"qr"`
	TC bool `json:"tc" msgpack:"tc"`
	AA bool `json:"aa" msgpack:"aa"`
	RA bool `json:"ra" msgpack:"ra"`
	AD bool `json:"ad" msgpack:"ad"`
}

type DnsGeo struct {
	City           string `json:"city" msgpack:"city"`
	Continent      string `json:"continent" msgpack:"continent"`
	CountryIsoCode string `json:"country-isocode" msgpack:"country-isocode"`
}

type DnsNetInfo struct {
	Family                 string `json:"family" msgpack:"family"`
	Protocol               string `json:"protocol" msgpack:"protocol"`
	QueryIp                string `json:"query-ip" msgpack:"query-ip"`
	QueryPort              string `json:"query-port" msgpack:"query-port"`
	ResponseIp             string `json:"response-ip" msgpack:"response-ip"`
	ResponsePort           string `json:"response-port" msgpack:"response-port"`
	AutonomousSystemNumber string `json:"as-number" msgpack:"as-number"`
	AutonomousSystemOrg    string `json:"as-owner" msgpack:"as-owner"`
}

type DnsRRs struct {
	Answers     []DnsAnswer `json:"an" msgpack:"an"`
	Nameservers []DnsAnswer `json:"ns" msgpack:"ns"`
	Records     []DnsAnswer `json:"ar" msgpack:"ar"`
}

type Dns struct {
	Type                     string   `json:"-" msgpack:"-"`
	Payload                  []byte   `json:"-" msgpack:"-"`
	Length                   int      `json:"length" msgpack:"-"`
	Id                       int      `json:"-" msgpack:"-"`
	Opcode                   int      `json:"opcode" msgpack:"opcode"`
	Rcode                    string   `json:"rcode" msgpack:"rcode"`
	Qname                    string   `json:"qname" msgpack:"qname"`
	QnamePublicSuffix        string   `json:"qname-public-suffix" msgpack:"qname-public-suffix"`
	QnameEffectiveTLDPlusOne string   `json:"qname-effective-tld-plus-one" msgpack:"qname-effective-tld-plus-one"`
	Qtype                    string   `json:"qtype" msgpack:"qtype"`
	Flags                    DnsFlags `json:"flags" msgpack:"flags"`
	DnsRRs                   DnsRRs   `json:"resource-records" msgpack:"resource-records"`
	MalformedPacket          bool     `json:"malformed-packet" msgpack:"malformed-packet"`
}

type DnsOption struct {
	Code int    `json:"code" msgpack:"code"`
	Name string `json:"name" msgpack:"name"`
	Data string `json:"data" msgpack:"data"`
}

type DnsExtended struct {
	UdpSize       int         `json:"udp-size" msgpack:"udp-size"`
	ExtendedRcode int         `json:"rcode" msgpack:"rcode"`
	Version       int         `json:"version" msgpack:"version"`
	Do            int         `json:"dnssec-ok" msgpack:"dnssec-ok"`
	Z             int         `json:"-" msgpack:"-"`
	Options       []DnsOption `json:"options" msgpack:"options"`
}

type DnsTap struct {
	Operation        string  `json:"operation" msgpack:"operation"`
	Identity         string  `json:"identity" msgpack:"identity"`
	TimestampRFC3339 string  `json:"timestamp-rfc3339ns" msgpack:"timestamp-rfc3339ns"`
	Timestamp        float64 `json:"-" msgpack:"-"`
	TimeSec          int     `json:"-" msgpack:"-"`
	TimeNsec         int     `json:"-" msgpack:"-"`
	Latency          float64 `json:"-" msgpack:"-"`
	LatencySec       string  `json:"latency" msgpack:"latency"`
}

type PowerDns struct {
	Tags                  []string `json:"tags" msgpack:"tags"`
	OriginalRequestSubnet string   `json:"original-request-subnet" msgpack:"original-request-subnet"`
	AppliedPolicy         string   `json:"applied-policy" msgpack:"applied-policy"`
}

type DnsMessage struct {
	NetworkInfo DnsNetInfo  `json:"network" msgpack:"network"`
	DNS         Dns         `json:"dns" msgpack:"dns"`
	EDNS        DnsExtended `json:"edns" msgpack:"edns"`
	DnsTap      DnsTap      `json:"dnstap" msgpack:"dnstap"`
	Geo         DnsGeo      `json:"geo" msgpack:"geo"`
	PowerDns    PowerDns    `json:"pdns" msgpack:"pdns"`
}

func (dm *DnsMessage) Init() {

	dm.NetworkInfo = DnsNetInfo{
		Family:                 "-",
		Protocol:               "-",
		QueryIp:                "-",
		QueryPort:              "-",
		ResponseIp:             "-",
		ResponsePort:           "-",
		AutonomousSystemNumber: "-",
		AutonomousSystemOrg:    "-",
	}

	dm.DnsTap = DnsTap{
		Operation:        "-",
		Identity:         "-",
		TimestampRFC3339: "-",
		LatencySec:       "-",
	}

	dm.DNS = Dns{
		Type:                     "-",
		MalformedPacket:          false,
		Rcode:                    "-",
		Qtype:                    "-",
		Qname:                    "-",
		QnamePublicSuffix:        "-",
		QnameEffectiveTLDPlusOne: "-",
		DnsRRs:                   DnsRRs{Answers: []DnsAnswer{}, Nameservers: []DnsAnswer{}, Records: []DnsAnswer{}},
	}

	dm.EDNS = DnsExtended{UdpSize: 0,
		ExtendedRcode: 0,
		Version:       0,
		Do:            0,
		Z:             0,
		Options:       []DnsOption{},
	}

	dm.Geo = DnsGeo{
		CountryIsoCode: "-",
		City:           "-",
		Continent:      "-",
	}

	dm.PowerDns = PowerDns{
		Tags:                  []string{},
		OriginalRequestSubnet: "",
		AppliedPolicy:         "",
	}
}

func (dm *DnsMessage) Bytes(format []string, delimiter string) []byte {
	var s bytes.Buffer

	for i, word := range format {
		switch word {
		case "ttl":
			if len(dm.DNS.DnsRRs.Answers) > 0 {
				s.WriteString(strconv.Itoa(dm.DNS.DnsRRs.Answers[0].Ttl))
			} else {
				s.WriteString("-")
			}
		case "answer":
			if len(dm.DNS.DnsRRs.Answers) > 0 {
				s.WriteString(dm.DNS.DnsRRs.Answers[0].Rdata)
			} else {
				s.WriteString("-")
			}
		case "edns-csubnet":
			if len(dm.EDNS.Options) > 0 {
				for _, opt := range dm.EDNS.Options {
					if opt.Name == "CSUBNET" {
						s.WriteString(opt.Data)
						break
					}
				}
			} else {
				s.WriteString("-")
			}
		case "answercount":
			s.WriteString(strconv.Itoa(len(dm.DNS.DnsRRs.Answers)))
		case "id":
			s.WriteString(strconv.Itoa(dm.DNS.Id))
		case "timestamp": // keep it just for backward compatibility
			s.WriteString(dm.DnsTap.TimestampRFC3339)
		case "timestamp-rfc3339ns":
			s.WriteString(dm.DnsTap.TimestampRFC3339)
		case "timestamp-unixms":
			s.WriteString(fmt.Sprintf("%.3f", dm.DnsTap.Timestamp))
		case "timestamp-unixus":
			s.WriteString(fmt.Sprintf("%.6f", dm.DnsTap.Timestamp))
		case "timestamp-unixns":
			s.WriteString(fmt.Sprintf("%.9f", dm.DnsTap.Timestamp))
		case "localtime":
			ts := time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))
			s.WriteString(ts.Format("2006-01-02 15:04:05.999999999"))
		case "identity":
			s.WriteString(dm.DnsTap.Identity)
		case "operation":
			s.WriteString(dm.DnsTap.Operation)
		case "rcode":
			s.WriteString(dm.DNS.Rcode)
		case "queryip":
			s.WriteString(dm.NetworkInfo.QueryIp)
		case "queryport":
			s.WriteString(dm.NetworkInfo.QueryPort)
		case "responseip":
			s.WriteString(dm.NetworkInfo.ResponseIp)
		case "responseport":
			s.WriteString(dm.NetworkInfo.ResponsePort)
		case "family":
			s.WriteString(dm.NetworkInfo.Family)
		case "protocol":
			s.WriteString(dm.NetworkInfo.Protocol)
		case "length":
			s.WriteString(strconv.Itoa(dm.DNS.Length) + "b")
		case "qname":
			s.WriteString(dm.DNS.Qname)
		case "qnamepublicsuffix":
			s.WriteString(dm.DNS.QnamePublicSuffix)
		case "qnameeffectivetldplusone":
			s.WriteString(dm.DNS.QnameEffectiveTLDPlusOne)
		case "qtype":
			s.WriteString(dm.DNS.Qtype)
		case "latency":
			s.WriteString(dm.DnsTap.LatencySec)
		case "continent":
			s.WriteString(dm.Geo.Continent)
		case "country":
			s.WriteString(dm.Geo.CountryIsoCode)
		case "city":
			s.WriteString(dm.Geo.City)
		case "as-number":
			s.WriteString(dm.NetworkInfo.AutonomousSystemNumber)
		case "as-owner":
			s.WriteString(dm.NetworkInfo.AutonomousSystemOrg)
		case "malformed":
			//s.WriteString(strconv.Itoa(dm.DNS.MalformedPacket))
			if dm.DNS.MalformedPacket {
				s.WriteString("PKTERR")
			} else {
				s.WriteString("-")
			}
		case "qr":
			s.WriteString(dm.DNS.Type)
		case "opcode":
			s.WriteString(strconv.Itoa(dm.DNS.Opcode))
		case "tc":
			if dm.DNS.Flags.TC {
				s.WriteString("TC")
			} else {
				s.WriteString("-")
			}
		case "aa":
			if dm.DNS.Flags.AA {
				s.WriteString("AA")
			} else {
				s.WriteString("-")
			}
		case "ra":
			if dm.DNS.Flags.RA {
				s.WriteString("RA")
			} else {
				s.WriteString("-")
			}
		case "ad":
			if dm.DNS.Flags.AD {
				s.WriteString("AD")
			} else {
				s.WriteString("-")
			}
		case "pdns-tags":
			if len(dm.PowerDns.Tags) > 0 {
				for _, tag := range dm.PowerDns.Tags {
					s.WriteString(tag)
				}
			} else {
				s.WriteString("-")
			}
		case "pdns-applied-policy":
			if len(dm.PowerDns.AppliedPolicy) > 0 {
				s.WriteString(dm.PowerDns.AppliedPolicy)
			} else {
				s.WriteString("-")
			}
		case "pdns-original-request-subnet":
			if len(dm.PowerDns.OriginalRequestSubnet) > 0 {
				s.WriteString(dm.PowerDns.OriginalRequestSubnet)
			} else {
				s.WriteString("-")
			}
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
	dm.DnsTap.Identity = "collector"
	dm.DnsTap.Operation = "CLIENT_QUERY"
	dm.DNS.Type = DnsQuery
	dm.DNS.Qname = "dns.collector"
	dm.NetworkInfo.QueryIp = "1.2.3.4"
	dm.NetworkInfo.QueryPort = "1234"
	dm.NetworkInfo.ResponseIp = "4.3.2.1"
	dm.NetworkInfo.ResponsePort = "4321"
	dm.DNS.Rcode = "NOERROR"
	dm.DNS.Qtype = "A"
	return dm
}
