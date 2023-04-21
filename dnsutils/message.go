package dnsutils

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nqd/flat"
	"google.golang.org/protobuf/proto"
)

var (
	DnsQuery               = "QUERY"
	DnsReply               = "REPLY"
	PdnsDirectives         = regexp.MustCompile(`^powerdns-*`)
	GeoIPDirectives        = regexp.MustCompile(`^geoip-*`)
	SuspiciousDirectives   = regexp.MustCompile(`^suspicious-*`)
	PublicSuffixDirectives = regexp.MustCompile(`^publixsuffix-*`)
	ExtractedDirectives    = regexp.MustCompile(`^extracted-*`)
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
	City                   string `json:"city" msgpack:"city"`
	Continent              string `json:"continent" msgpack:"continent"`
	CountryIsoCode         string `json:"country-isocode" msgpack:"country-isocode"`
	AutonomousSystemNumber string `json:"as-number" msgpack:"as-number"`
	AutonomousSystemOrg    string `json:"as-owner" msgpack:"as-owner"`
}

type DnsNetInfo struct {
	Family         string `json:"family" msgpack:"family"`
	Protocol       string `json:"protocol" msgpack:"protocol"`
	QueryIp        string `json:"query-ip" msgpack:"query-ip"`
	QueryPort      string `json:"query-port" msgpack:"query-port"`
	ResponseIp     string `json:"response-ip" msgpack:"response-ip"`
	ResponsePort   string `json:"response-port" msgpack:"response-port"`
	IpDefragmented bool   `json:"ip-defragmented" msgpack:"ip-defragmented"`
	TcpReassembled bool   `json:"tcp-reassembled" msgpack:"tcp-reassembled"`
}

type DnsRRs struct {
	Answers     []DnsAnswer `json:"an" msgpack:"an"`
	Nameservers []DnsAnswer `json:"ns" msgpack:"ns"`
	Records     []DnsAnswer `json:"ar" msgpack:"ar"`
}

type Dns struct {
	Type    string `json:"-" msgpack:"-"`
	Payload []byte `json:"-" msgpack:"-"`
	Length  int    `json:"length" msgpack:"-"`
	Id      int    `json:"-" msgpack:"-"`
	Opcode  int    `json:"opcode" msgpack:"opcode"`
	Rcode   string `json:"rcode" msgpack:"rcode"`
	Qname   string `json:"qname" msgpack:"qname"`

	Qtype           string   `json:"qtype" msgpack:"qtype"`
	Flags           DnsFlags `json:"flags" msgpack:"flags"`
	DnsRRs          DnsRRs   `json:"resource-records" msgpack:"resource-records"`
	MalformedPacket bool     `json:"malformed-packet" msgpack:"malformed-packet"`

	Repeated int `json:"repeated" msgpack:"repeated"`
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
	Version          string  `json:"version" msgpack:"version"`
	TimestampRFC3339 string  `json:"timestamp-rfc3339ns" msgpack:"timestamp-rfc3339ns"`
	Timestamp        float64 `json:"-" msgpack:"-"`
	TimeSec          int     `json:"-" msgpack:"-"`
	TimeNsec         int     `json:"-" msgpack:"-"`
	Latency          float64 `json:"-" msgpack:"-"`
	LatencySec       string  `json:"latency" msgpack:"latency"`
	Payload          []byte  `json:"-" msgpack:"-"`
}

type PowerDns struct {
	Tags                  []string          `json:"tags" msgpack:"tags"`
	OriginalRequestSubnet string            `json:"original-request-subnet" msgpack:"original-request-subnet"`
	AppliedPolicy         string            `json:"applied-policy" msgpack:"applied-policy"`
	Metadata              map[string]string `json:"metadata" msgpack:"metadata"`
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

type PublicSuffix struct {
	QnamePublicSuffix        string `json:"tld" msgpack:"qname-public-suffix"`
	QnameEffectiveTLDPlusOne string `json:"etld+1" msgpack:"qname-effective-tld-plus-one"`
}

type DnsMessage struct {
	NetworkInfo  DnsNetInfo    `json:"network" msgpack:"network"`
	DNS          Dns           `json:"dns" msgpack:"dns"`
	EDNS         DnsExtended   `json:"edns" msgpack:"edns"`
	DnsTap       DnsTap        `json:"dnstap" msgpack:"dnstap"`
	Geo          *DnsGeo       `json:"geoip,omitempty" msgpack:"geo"`
	PowerDns     *PowerDns     `json:"powerdns,omitempty" msgpack:"powerdns"`
	Suspicious   *Suspicious   `json:"suspicious,omitempty" msgpack:"suspicious"`
	PublicSuffix *PublicSuffix `json:"publicsuffix,omitempty" msgpack:"publicsuffix"`
	Extracted    *Extracted    `json:"extracted,omitempty" msgpack:"extracted"`
}

type Extracted struct {
	Base64Payload []byte `json:"dns_payload" msgpack:"dns_payload"`
}

func (dm *DnsMessage) Init() {
	dm.NetworkInfo = DnsNetInfo{
		Family:         "-",
		Protocol:       "-",
		QueryIp:        "-",
		QueryPort:      "-",
		ResponseIp:     "-",
		ResponsePort:   "-",
		IpDefragmented: false,
		TcpReassembled: false,
	}

	dm.DnsTap = DnsTap{
		Operation:        "-",
		Identity:         "-",
		Version:          "-",
		TimestampRFC3339: "-",
		LatencySec:       "-",
	}

	dm.DNS = Dns{
		Type:            "-",
		MalformedPacket: false,
		Rcode:           "-",
		Qtype:           "-",
		Qname:           "-",
		DnsRRs:          DnsRRs{Answers: []DnsAnswer{}, Nameservers: []DnsAnswer{}, Records: []DnsAnswer{}},
		Repeated:        -1,
	}

	dm.EDNS = DnsExtended{
		UdpSize:       0,
		ExtendedRcode: 0,
		Version:       0,
		Do:            0,
		Z:             0,
		Options:       []DnsOption{},
	}

}

func (dm *DnsMessage) handleGeoIPDirectives(directives []string, s *bytes.Buffer) {
	if dm.Geo == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "geoip-continent":
			s.WriteString(dm.Geo.Continent)
		case directive == "geoip-country":
			s.WriteString(dm.Geo.CountryIsoCode)
		case directive == "geoip-city":
			s.WriteString(dm.Geo.City)
		case directive == "geoip-as-number":
			s.WriteString(dm.Geo.AutonomousSystemNumber)
		case directive == "geoip-as-owner":
			s.WriteString(dm.Geo.AutonomousSystemOrg)
		}
	}
}

func (dm *DnsMessage) handlePdnsDirectives(directives []string, s *bytes.Buffer) {
	if dm.PowerDns == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "powerdns-tags":
			if dm.PowerDns.Tags == nil {
				s.WriteString("-")
			} else {
				if len(dm.PowerDns.Tags) > 0 {
					if len(directives) == 2 {
						tag_index, err := strconv.Atoi(directives[1])
						if err != nil {
							log.Fatalf("unsupport tag index provided (integer expected): %s", directives[1])
						}
						if tag_index >= len(dm.PowerDns.Tags) {
							s.WriteString("-")
						} else {
							s.WriteString(dm.PowerDns.Tags[tag_index])
						}
					} else {
						for i, tag := range dm.PowerDns.Tags {
							s.WriteString(tag)
							// add separator
							if i+1 < len(dm.PowerDns.Tags) {
								s.WriteString(",")
							}
						}
					}
				} else {
					s.WriteString("-")
				}
			}
		case directive == "powerdns-applied-policy":
			if len(dm.PowerDns.AppliedPolicy) > 0 {
				s.WriteString(dm.PowerDns.AppliedPolicy)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-original-request-subnet":
			if len(dm.PowerDns.OriginalRequestSubnet) > 0 {
				s.WriteString(dm.PowerDns.OriginalRequestSubnet)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-metadata":
			if dm.PowerDns.Metadata == nil {
				s.WriteString("-")
			} else {
				if len(dm.PowerDns.Metadata) > 0 && len(directives) == 2 {
					if metaValue, ok := dm.PowerDns.Metadata[directives[1]]; ok {
						if len(metaValue) > 0 {
							s.WriteString(strings.Replace(metaValue, " ", "_", -1))
						} else {
							s.WriteString("-")
						}
					} else {
						s.WriteString("-")
					}
				} else {
					s.WriteString("-")
				}
			}
		}
	}
}

func (dm *DnsMessage) handleSuspiciousDirectives(directives []string, s *bytes.Buffer) {
	if dm.PowerDns == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "suspicious-score":
			s.WriteString(strconv.Itoa(int(dm.Suspicious.Score)))
		}
	}
}

func (dm *DnsMessage) handlePublicSuffixDirectives(directives []string, s *bytes.Buffer) {
	if dm.PublicSuffix == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "publixsuffix-tld":
			s.WriteString(dm.PublicSuffix.QnamePublicSuffix)
		case directive == "publixsuffix-etld+1":
			s.WriteString(dm.PublicSuffix.QnameEffectiveTLDPlusOne)
		}
	}
}

func (dm *DnsMessage) handleExtractedDirectives(directives []string, s *bytes.Buffer) {
	if dm.Extracted == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "extracted-dns-payload":
			if len(dm.DNS.Payload) > 0 {
				dst := make([]byte, base64.StdEncoding.EncodedLen(len(dm.DNS.Payload)))
				base64.StdEncoding.Encode(dst, dm.DNS.Payload)
				s.Write(dst)
			} else {
				s.WriteString("-")
			}
		}
	}
}

func (dm *DnsMessage) Bytes(format []string, fieldDelimiter string, fieldBoundary string) []byte {
	var s bytes.Buffer

	for i, word := range format {
		directives := strings.SplitN(word, ":", 2)
		switch directive := directives[0]; {
		// default directives
		case directive == "ttl":
			if len(dm.DNS.DnsRRs.Answers) > 0 {
				s.WriteString(strconv.Itoa(dm.DNS.DnsRRs.Answers[0].Ttl))
			} else {
				s.WriteString("-")
			}
		case directive == "answer":
			if len(dm.DNS.DnsRRs.Answers) > 0 {
				s.WriteString(dm.DNS.DnsRRs.Answers[0].Rdata)
			} else {
				s.WriteString("-")
			}
		case directive == "edns-csubnet":
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
		case directive == "answercount":
			s.WriteString(strconv.Itoa(len(dm.DNS.DnsRRs.Answers)))
		case directive == "id":
			s.WriteString(strconv.Itoa(dm.DNS.Id))
		case directive == "timestamp": // keep it just for backward compatibility
			s.WriteString(dm.DnsTap.TimestampRFC3339)
		case directive == "timestamp-rfc3339ns":
			s.WriteString(dm.DnsTap.TimestampRFC3339)
		case directive == "timestamp-unixms":
			s.WriteString(fmt.Sprintf("%.3f", dm.DnsTap.Timestamp))
		case directive == "timestamp-unixus":
			s.WriteString(fmt.Sprintf("%.6f", dm.DnsTap.Timestamp))
		case directive == "timestamp-unixns":
			s.WriteString(fmt.Sprintf("%.9f", dm.DnsTap.Timestamp))
		case directive == "localtime":
			ts := time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))
			s.WriteString(ts.Format("2006-01-02 15:04:05.999999999"))
		case directive == "identity":
			s.WriteString(dm.DnsTap.Identity)
		case directive == "version":
			s.WriteString(dm.DnsTap.Version)
		case directive == "operation":
			s.WriteString(dm.DnsTap.Operation)
		case directive == "rcode":
			s.WriteString(dm.DNS.Rcode)
		case directive == "queryip":
			s.WriteString(dm.NetworkInfo.QueryIp)
		case directive == "queryport":
			s.WriteString(dm.NetworkInfo.QueryPort)
		case directive == "responseip":
			s.WriteString(dm.NetworkInfo.ResponseIp)
		case directive == "responseport":
			s.WriteString(dm.NetworkInfo.ResponsePort)
		case directive == "family":
			s.WriteString(dm.NetworkInfo.Family)
		case directive == "protocol":
			s.WriteString(dm.NetworkInfo.Protocol)
		case directive == "length":
			s.WriteString(strconv.Itoa(dm.DNS.Length) + "b")
		case directive == "qname":
			if strings.Contains(dm.DNS.Qname, fieldDelimiter) {
				qname := dm.DNS.Qname
				if strings.Contains(qname, fieldBoundary) {
					qname = strings.ReplaceAll(qname, fieldBoundary, "\\"+fieldBoundary)
				}
				s.WriteString(fmt.Sprintf(fieldBoundary+"%s"+fieldBoundary, qname))
			} else {
				s.WriteString(dm.DNS.Qname)
			}
		case directive == "qtype":
			s.WriteString(dm.DNS.Qtype)
		case directive == "latency":
			s.WriteString(dm.DnsTap.LatencySec)
		case directive == "malformed":
			//s.WriteString(strconv.Itoa(dm.DNS.MalformedPacket))
			if dm.DNS.MalformedPacket {
				s.WriteString("PKTERR")
			} else {
				s.WriteString("-")
			}
		case directive == "qr":
			s.WriteString(dm.DNS.Type)
		case directive == "opcode":
			s.WriteString(strconv.Itoa(dm.DNS.Opcode))
		case directive == "tr":
			if dm.NetworkInfo.TcpReassembled {
				s.WriteString("TR")
			} else {
				s.WriteString("-")
			}
		case directive == "df":
			if dm.NetworkInfo.IpDefragmented {
				s.WriteString("DF")
			} else {
				s.WriteString("-")
			}
		case directive == "tc":
			if dm.DNS.Flags.TC {
				s.WriteString("TC")
			} else {
				s.WriteString("-")
			}
		case directive == "aa":
			if dm.DNS.Flags.AA {
				s.WriteString("AA")
			} else {
				s.WriteString("-")
			}
		case directive == "ra":
			if dm.DNS.Flags.RA {
				s.WriteString("RA")
			} else {
				s.WriteString("-")
			}
		case directive == "ad":
			if dm.DNS.Flags.AD {
				s.WriteString("AD")
			} else {
				s.WriteString("-")
			}
		case directive == "repeated":
			s.WriteString(strconv.Itoa(dm.DNS.Repeated))
		// more directives from collectors
		case PdnsDirectives.MatchString(directive):
			dm.handlePdnsDirectives(directives, &s)
		// more directives from transformers
		case GeoIPDirectives.MatchString(directive):
			dm.handleGeoIPDirectives(directives, &s)
		case SuspiciousDirectives.MatchString(directive):
			dm.handleSuspiciousDirectives(directives, &s)
		case PublicSuffixDirectives.MatchString(directive):
			dm.handlePublicSuffixDirectives(directives, &s)
		case ExtractedDirectives.MatchString(directive):
			dm.handleExtractedDirectives(directives, &s)
		// error unsupport directive for text format
		default:
			log.Fatalf("unsupport directive for text format: %s", word)
		}

		if i < len(format)-1 {
			s.WriteString(fieldDelimiter)
		}
	}

	return s.Bytes()
}

func (dm *DnsMessage) String(format []string, fieldDelimiter string, fieldBoundary string) string {
	return string(dm.Bytes(format, fieldDelimiter, fieldBoundary))
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

	var sf dnstap.SocketFamily
	if ipNet, valid := IP_TO_INET[dm.NetworkInfo.Family]; valid {
		sf = dnstap.SocketFamily(dnstap.SocketFamily_value[ipNet])
	}
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

	reqIp := net.ParseIP(dm.NetworkInfo.QueryIp)
	if dm.NetworkInfo.Family == PROTO_IPV4 {
		msg.QueryAddress = reqIp.To4()
	} else {
		msg.QueryAddress = reqIp.To16()
	}
	msg.QueryPort = &qport

	rspIp := net.ParseIP(dm.NetworkInfo.ResponseIp)
	if dm.NetworkInfo.Family == PROTO_IPV4 {
		msg.ResponseAddress = rspIp.To4()
	} else {
		msg.ResponseAddress = rspIp.To16()
	}
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
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip6 := &layers.IPv6{Version: 6}
	udp := &layers.UDP{}
	tcp := &layers.TCP{}

	// prepare ip
	srcIp, srcPort, dstIp, dstPort := GetIpPort(dm)

	// packet layer array
	pkt := []gopacket.SerializableLayer{}

	// set source and destination IP
	switch dm.NetworkInfo.Family {
	case PROTO_IPV4:
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4.SrcIP = net.ParseIP(srcIp)
		ip4.DstIP = net.ParseIP(dstIp)
	case PROTO_IPV6:
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6.SrcIP = net.ParseIP(srcIp)
		ip6.DstIP = net.ParseIP(dstIp)
	default:
		return nil, errors.New("family " + dm.NetworkInfo.Family + " not yet implemented")
	}

	// set transport
	switch dm.NetworkInfo.Protocol {

	// DNS over UDP
	case PROTO_UDP:
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)

		// update iplayer
		switch dm.NetworkInfo.Family {
		case PROTO_IPV4:
			ip4.Protocol = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4)
		case PROTO_IPV6:
			ip6.NextHeader = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6)
		}

	// DNS over TCP
	case PROTO_TCP:
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.PSH = true
		tcp.Window = 65535

		// dns length
		dnsLengthField := make([]byte, 2)
		binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.DNS.Length))

		// update iplayer
		switch dm.NetworkInfo.Family {
		case PROTO_IPV4:
			ip4.Protocol = layers.IPProtocolTCP
			tcp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip4)
		case PROTO_IPV6:
			ip6.NextHeader = layers.IPProtocolTCP
			tcp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip6)
		}

	// DNS over HTTPS and DNS over TLS
	// These protocols are translated to DNS over UDP
	case PROTO_DOH, PROTO_DOT:
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)

		// update iplayer
		switch dm.NetworkInfo.Family {
		case PROTO_IPV4:
			ip4.Protocol = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4)
		case PROTO_IPV6:
			ip6.NextHeader = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6)
		}

	default:
		return nil, errors.New("protocol " + dm.NetworkInfo.Protocol + " not yet implemented")
	}

	pkt = append(pkt, eth)

	return pkt, nil
}

func (dm *DnsMessage) Flatten() (ret map[string]interface{}, err error) {
	// TODO perhaps panic when flattening fails, as it should always work.
	var tmp []byte
	if tmp, err = json.Marshal(dm); err != nil {
		return
	}
	json.Unmarshal(tmp, &ret)
	ret, err = flat.Flatten(ret, nil)
	return
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
