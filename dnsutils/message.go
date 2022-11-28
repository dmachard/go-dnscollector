package dnsutils

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/protobuf/proto"
)

var (
	DnsQuery = "QUERY"
	DnsReply = "REPLY"
)

func GetIpPort(dm *DnsMessage) (string, int, string, int) {
	srcIp, srcPort := "0.0.0.0", 53
	dstIp, dstPort := "0.0.0.0", 53
	if dm.NetworkInfo.Family == "INET6" {
		srcIp, dstIp = "::", "::"
	}

	if dm.NetworkInfo.QueryIp != "-" {
		srcIp = dm.NetworkInfo.QueryIp
		srcPort, _ = strconv.Atoi(dm.NetworkInfo.QueryPort)
	}
	if dm.NetworkInfo.ResponseIp != "-" {
		dstIp = dm.NetworkInfo.ResponseIp
		dstPort, _ = strconv.Atoi(dm.NetworkInfo.ResponsePort)
	}

	// reverse destination and source
	if dm.DNS.Type == DnsReply {
		srcIp_tmp, srcPort_tmp := srcIp, srcPort
		srcIp, srcPort = dstIp, dstPort
		dstIp, dstPort = srcIp_tmp, srcPort_tmp
	}
	return srcIp, srcPort, dstIp, dstPort
}

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
	Payload          []byte  `json:"-" msgpack:"-"`
}

type PowerDns struct {
	Tags                  []string `json:"tags" msgpack:"tags"`
	OriginalRequestSubnet string   `json:"original-request-subnet" msgpack:"original-request-subnet"`
	AppliedPolicy         string   `json:"applied-policy" msgpack:"applied-policy"`
}

type Suspicious struct {
	Score                 float64 `json:"score" msgpack:"score"`
	MalformedPacket       bool    `json:"malformed-pkt" msgpack:"malformed-pkt"`
	LargePacket           bool    `json:"large-pkt" msgpack:"large-pkt"`
	LongDomain            bool    `json:"long-domain" msgpack:"long-domain"`
	SlowDomain            bool    `json:"slow-domain" msgpack:"slow-domain"`
	UnallowedChars        bool    `json:"unallowed-chars" msgpack:"unallowed-chars"`
	UncommonQtypes        bool    `json:"uncommon-qtypes" msgpack:"uncommon-qtypes"`
	ExcessiveNumberLabels bool    `json:"excessive-number-labels" msgpack:"excessive-number-labels"`
}

type DnsMessage struct {
	NetworkInfo DnsNetInfo  `json:"network" msgpack:"network"`
	DNS         Dns         `json:"dns" msgpack:"dns"`
	EDNS        DnsExtended `json:"edns" msgpack:"edns"`
	DnsTap      DnsTap      `json:"dnstap" msgpack:"dnstap"`
	Geo         DnsGeo      `json:"geo" msgpack:"geo"`
	PowerDns    PowerDns    `json:"pdns" msgpack:"pdns"`
	Suspicious  Suspicious  `json:"suspicious" msgpack:"suspicious"`
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

	dm.EDNS = DnsExtended{
		UdpSize:       0,
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

	dm.Suspicious = Suspicious{
		Score:                 0.0,
		MalformedPacket:       false,
		LargePacket:           false,
		LongDomain:            false,
		SlowDomain:            false,
		UnallowedChars:        false,
		UncommonQtypes:        false,
		ExcessiveNumberLabels: false,
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
				for i, tag := range dm.PowerDns.Tags {
					s.WriteString(tag)
					// add separator
					if i+1 < len(dm.PowerDns.Tags) {
						s.WriteString(",")
					}
				}
			} else {
				s.WriteString("-")
			}
		case "pdns-tag":
			if len(dm.PowerDns.Tags) > 0 {
				s.WriteString(dm.PowerDns.Tags[0])
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
		case "suspicious-score":
			s.WriteString(strconv.Itoa(int(dm.Suspicious.Score)))
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

func (dm *DnsMessage) ToDnstap() ([]byte, error) {
	if len(dm.DnsTap.Payload) > 0 {
		return dm.DnsTap.Payload, nil
	}

	dt := &dnstap.Dnstap{}
	t := dnstap.Dnstap_MESSAGE
	dt.Identity = []byte(dm.DnsTap.Identity)
	dt.Version = []byte("-")
	dt.Type = &t

	mt := dnstap.Message_Type(dnstap.Message_Type_value[dm.DnsTap.Operation])
	sf := dnstap.SocketFamily(dnstap.SocketFamily_value[dm.NetworkInfo.Family])
	sp := dnstap.SocketProtocol(dnstap.SocketProtocol_value[dm.NetworkInfo.Protocol])
	tsec := uint64(dm.DnsTap.TimeSec)
	tnsec := uint32(dm.DnsTap.TimeNsec)

	var rport uint32
	var qport uint32
	if dm.NetworkInfo.ResponsePort != "-" {
		if port, err := strconv.Atoi(dm.NetworkInfo.ResponsePort); err != nil {
			return nil, err
		} else {
			rport = uint32(port)
		}
	}

	if dm.NetworkInfo.QueryPort != "-" {
		if port, err := strconv.Atoi(dm.NetworkInfo.QueryPort); err != nil {
			return nil, err
		} else {
			qport = uint32(port)
		}
	}

	msg := &dnstap.Message{Type: &mt}

	msg.SocketFamily = &sf
	msg.SocketProtocol = &sp
	msg.QueryAddress = net.ParseIP(dm.NetworkInfo.QueryIp)
	msg.QueryPort = &qport
	msg.ResponseAddress = net.ParseIP(dm.NetworkInfo.ResponseIp)
	msg.ResponsePort = &rport

	if dm.DNS.Type == DnsQuery {
		msg.QueryMessage = dm.DNS.Payload
		msg.QueryTimeSec = &tsec
		msg.QueryTimeNsec = &tnsec
	} else {
		msg.ResponseTimeSec = &tsec
		msg.ResponseTimeNsec = &tnsec
		msg.ResponseMessage = dm.DNS.Payload
	}

	dt.Message = msg

	data, err := proto.Marshal(dt)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (dm *DnsMessage) ToPacketLayer() ([]gopacket.SerializableLayer, error) {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip6 := &layers.IPv6{Version: 6}
	udp := &layers.UDP{}
	tcp := &layers.TCP{}

	// prepare ip
	srcIp, srcPort, dstIp, dstPort := GetIpPort(dm)

	// packet layer array
	pkt := []gopacket.SerializableLayer{}

	// set ip and transport
	if dm.NetworkInfo.Family == PROTO_IPV6 && dm.NetworkInfo.Protocol == PROTO_UDP {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6.SrcIP = net.ParseIP(srcIp)
		ip6.DstIP = net.ParseIP(dstIp)
		ip6.NextHeader = layers.IPProtocolUDP
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)
		udp.SetNetworkLayerForChecksum(ip6)

		pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6, eth)

	} else if dm.NetworkInfo.Family == PROTO_IPV6 && dm.NetworkInfo.Protocol == PROTO_TCP {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6.SrcIP = net.ParseIP(srcIp)
		ip6.DstIP = net.ParseIP(dstIp)
		ip6.NextHeader = layers.IPProtocolTCP
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.PSH = true
		tcp.Window = 65535
		tcp.SetNetworkLayerForChecksum(ip6)

		dnsLengthField := make([]byte, 2)
		binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.DNS.Length))
		pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip6, eth)

	} else if dm.NetworkInfo.Family == PROTO_IPV4 && dm.NetworkInfo.Protocol == PROTO_UDP {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4.SrcIP = net.ParseIP(srcIp)
		ip4.DstIP = net.ParseIP(dstIp)
		ip4.Protocol = layers.IPProtocolUDP
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)
		udp.SetNetworkLayerForChecksum(ip4)

		pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4, eth)

	} else if dm.NetworkInfo.Family == PROTO_IPV4 && dm.NetworkInfo.Protocol == PROTO_TCP {
		// SYN
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4.SrcIP = net.ParseIP(srcIp)
		ip4.DstIP = net.ParseIP(dstIp)
		ip4.Protocol = layers.IPProtocolTCP
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.PSH = true
		tcp.Window = 65535
		tcp.SetNetworkLayerForChecksum(ip4)

		dnsLengthField := make([]byte, 2)
		binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.DNS.Length))
		pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip4, eth)

	} else {
		// ignore other packet
		return nil, errors.New("not yet implemented")
	}
	return pkt, nil
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
