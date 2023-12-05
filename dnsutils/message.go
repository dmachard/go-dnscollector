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

	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/nqd/flat"
	"google.golang.org/protobuf/proto"
)

var (
	DNSQuery                  = "QUERY"
	DNSReply                  = "REPLY"
	PdnsDirectives            = regexp.MustCompile(`^powerdns-*`)
	GeoIPDirectives           = regexp.MustCompile(`^geoip-*`)
	SuspiciousDirectives      = regexp.MustCompile(`^suspicious-*`)
	PublicSuffixDirectives    = regexp.MustCompile(`^publixsuffix-*`)
	ExtractedDirectives       = regexp.MustCompile(`^extracted-*`)
	ReducerDirectives         = regexp.MustCompile(`^reducer-*`)
	MachineLearningDirectives = regexp.MustCompile(`^ml-*`)
	FilteringDirectives       = regexp.MustCompile(`^filtering-*`)
)

func GetIPPort(dm *DNSMessage) (string, int, string, int) {
	srcIP, srcPort := "0.0.0.0", 53
	dstIP, dstPort := "0.0.0.0", 53
	if dm.NetworkInfo.Family == "INET6" {
		srcIP, dstIP = "::", "::"
	}

	if dm.NetworkInfo.QueryIP != "-" {
		srcIP = dm.NetworkInfo.QueryIP
		srcPort, _ = strconv.Atoi(dm.NetworkInfo.QueryPort)
	}
	if dm.NetworkInfo.ResponseIP != "-" {
		dstIP = dm.NetworkInfo.ResponseIP
		dstPort, _ = strconv.Atoi(dm.NetworkInfo.ResponsePort)
	}

	// reverse destination and source
	if dm.DNS.Type == DNSReply {
		srcIPTmp, srcPortTmp := srcIP, srcPort
		srcIP, srcPort = dstIP, dstPort
		dstIP, dstPort = srcIPTmp, srcPortTmp
	}
	return srcIP, srcPort, dstIP, dstPort
}

type DNSAnswer struct {
	Name      string `json:"name" msgpack:"name"`
	Rdatatype string `json:"rdatatype" msgpack:"rdatatype"`
	Class     int    `json:"-" msgpack:"-"`
	TTL       int    `json:"ttl" msgpack:"ttl"`
	Rdata     string `json:"rdata" msgpack:"rdata"`
}

type DNSFlags struct {
	QR bool `json:"qr" msgpack:"qr"`
	TC bool `json:"tc" msgpack:"tc"`
	AA bool `json:"aa" msgpack:"aa"`
	RA bool `json:"ra" msgpack:"ra"`
	AD bool `json:"ad" msgpack:"ad"`
}

type DNSNetInfo struct {
	Family         string `json:"family" msgpack:"family"`
	Protocol       string `json:"protocol" msgpack:"protocol"`
	QueryIP        string `json:"query-ip" msgpack:"query-ip"`
	QueryPort      string `json:"query-port" msgpack:"query-port"`
	ResponseIP     string `json:"response-ip" msgpack:"response-ip"`
	ResponsePort   string `json:"response-port" msgpack:"response-port"`
	IPDefragmented bool   `json:"ip-defragmented" msgpack:"ip-defragmented"`
	TCPReassembled bool   `json:"tcp-reassembled" msgpack:"tcp-reassembled"`
}

type DNSRRs struct {
	Answers     []DNSAnswer `json:"an" msgpack:"an"`
	Nameservers []DNSAnswer `json:"ns" msgpack:"ns"`
	Records     []DNSAnswer `json:"ar" msgpack:"ar"`
}

type DNS struct {
	Type    string `json:"-" msgpack:"-"`
	Payload []byte `json:"-" msgpack:"-"`
	Length  int    `json:"length" msgpack:"-"`
	ID      int    `json:"-" msgpack:"-"`
	Opcode  int    `json:"opcode" msgpack:"opcode"`
	Rcode   string `json:"rcode" msgpack:"rcode"`
	Qname   string `json:"qname" msgpack:"qname"`

	Qtype           string   `json:"qtype" msgpack:"qtype"`
	Flags           DNSFlags `json:"flags" msgpack:"flags"`
	DNSRRs          DNSRRs   `json:"resource-records" msgpack:"resource-records"`
	MalformedPacket bool     `json:"malformed-packet" msgpack:"malformed-packet"`
}

type DNSOption struct {
	Code int    `json:"code" msgpack:"code"`
	Name string `json:"name" msgpack:"name"`
	Data string `json:"data" msgpack:"data"`
}

type DNSExtended struct {
	UDPSize       int         `json:"udp-size" msgpack:"udp-size"`
	ExtendedRcode int         `json:"rcode" msgpack:"rcode"`
	Version       int         `json:"version" msgpack:"version"`
	Do            int         `json:"dnssec-ok" msgpack:"dnssec-ok"`
	Z             int         `json:"-" msgpack:"-"`
	Options       []DNSOption `json:"options" msgpack:"options"`
}

type DNSTap struct {
	Operation        string  `json:"operation" msgpack:"operation"`
	Identity         string  `json:"identity" msgpack:"identity"`
	Version          string  `json:"version" msgpack:"version"`
	TimestampRFC3339 string  `json:"timestamp-rfc3339ns" msgpack:"timestamp-rfc3339ns"`
	Timestamp        int64   `json:"-" msgpack:"-"`
	TimeSec          int     `json:"-" msgpack:"-"`
	TimeNsec         int     `json:"-" msgpack:"-"`
	Latency          float64 `json:"-" msgpack:"-"`
	LatencySec       string  `json:"latency" msgpack:"latency"`
	Payload          []byte  `json:"-" msgpack:"-"`
	Extra            string  `json:"extra" msgpack:"extra"`
}

type PowerDNS struct {
	Tags                  []string          `json:"tags" msgpack:"tags"`
	OriginalRequestSubnet string            `json:"original-request-subnet" msgpack:"original-request-subnet"`
	AppliedPolicy         string            `json:"applied-policy" msgpack:"applied-policy"`
	Metadata              map[string]string `json:"metadata" msgpack:"metadata"`
}

type TransformDNSGeo struct {
	City                   string `json:"city" msgpack:"city"`
	Continent              string `json:"continent" msgpack:"continent"`
	CountryIsoCode         string `json:"country-isocode" msgpack:"country-isocode"`
	AutonomousSystemNumber string `json:"as-number" msgpack:"as-number"`
	AutonomousSystemOrg    string `json:"as-owner" msgpack:"as-owner"`
}

type TransformSuspicious struct {
	Score                 float64 `json:"score" msgpack:"score"`
	MalformedPacket       bool    `json:"malformed-pkt" msgpack:"malformed-pkt"`
	LargePacket           bool    `json:"large-pkt" msgpack:"large-pkt"`
	LongDomain            bool    `json:"long-domain" msgpack:"long-domain"`
	SlowDomain            bool    `json:"slow-domain" msgpack:"slow-domain"`
	UnallowedChars        bool    `json:"unallowed-chars" msgpack:"unallowed-chars"`
	UncommonQtypes        bool    `json:"uncommon-qtypes" msgpack:"uncommon-qtypes"`
	ExcessiveNumberLabels bool    `json:"excessive-number-labels" msgpack:"excessive-number-labels"`
	Domain                string  `json:"domain,omitempty" msgpack:"-"`
}

type TransformPublicSuffix struct {
	QnamePublicSuffix        string `json:"tld" msgpack:"qname-public-suffix"`
	QnameEffectiveTLDPlusOne string `json:"etld+1" msgpack:"qname-effective-tld-plus-one"`
}

type TransformExtracted struct {
	Base64Payload []byte `json:"dns_payload" msgpack:"dns_payload"`
}

type TransformReducer struct {
	Occurences       int `json:"occurences" msgpack:"occurences"`
	CumulativeLength int `json:"cumulative-length" msgpack:"cumulative-length"`
}

type TransformFiltering struct {
	SampleRate int `json:"sample-rate" msgpack:"sample-rate"`
}

type TransformML struct {
	Entropy               float64 `json:"entropy" msgpack:"entropy"`   // Entropy of query name
	Length                int     `json:"length" msgpack:"length"`     // Length of domain
	Labels                int     `json:"labels" msgpack:"labels"`     // Number of labels in the query name  separated by dots
	Digits                int     `json:"digits" msgpack:"digits"`     // Count of numerical characters
	Lowers                int     `json:"lowers" msgpack:"lowers"`     // Count of lowercase characters
	Uppers                int     `json:"uppers" msgpack:"uppers"`     // Count of uppercase characters
	Specials              int     `json:"specials" msgpack:"specials"` // Number of special characters; special characters such as dash, underscore, equal sign,...
	Others                int     `json:"others" msgpack:"others"`
	RatioDigits           float64 `json:"ratio-digits" msgpack:"ratio-digits"`
	RatioLetters          float64 `json:"ratio-letters" msgpack:"ratio-letters"`
	RatioSpecials         float64 `json:"ratio-specials" msgpack:"ratio-specials"`
	RatioOthers           float64 `json:"ratio-others" msgpack:"ratio-others"`
	ConsecutiveChars      int     `json:"consecutive-chars" msgpack:"consecutive-chars"`
	ConsecutiveVowels     int     `json:"consecutive-vowels" msgpack:"consecutive-vowels"`
	ConsecutiveDigits     int     `json:"consecutive-digits" msgpack:"consecutive-digits"`
	ConsecutiveConsonants int     `json:"consecutive-consonants" msgpack:"consecutive-consonants"`
	Size                  int     `json:"size" msgpack:"size"`
	Occurences            int     `json:"occurences" msgpack:"occurences"`
	UncommonQtypes        int     `json:"uncommon-qtypes" msgpack:"uncommon-qtypes"`
}

type DNSMessage struct {
	NetworkInfo     DNSNetInfo             `json:"network" msgpack:"network"`
	DNS             DNS                    `json:"dns" msgpack:"dns"`
	EDNS            DNSExtended            `json:"edns" msgpack:"edns"`
	DNSTap          DNSTap                 `json:"dnstap" msgpack:"dnstap"`
	Geo             *TransformDNSGeo       `json:"geoip,omitempty" msgpack:"geo"`
	PowerDNS        *PowerDNS              `json:"powerdns,omitempty" msgpack:"powerdns"`
	Suspicious      *TransformSuspicious   `json:"suspicious,omitempty" msgpack:"suspicious"`
	PublicSuffix    *TransformPublicSuffix `json:"publicsuffix,omitempty" msgpack:"publicsuffix"`
	Extracted       *TransformExtracted    `json:"extracted,omitempty" msgpack:"extracted"`
	Reducer         *TransformReducer      `json:"reducer,omitempty" msgpack:"reducer"`
	MachineLearning *TransformML           `json:"ml,omitempty" msgpack:"ml"`
	Filtering       *TransformFiltering    `json:"filtering,omitempty" msgpack:"filtering"`
}

func (dm *DNSMessage) Init() {
	dm.NetworkInfo = DNSNetInfo{
		Family:         "-",
		Protocol:       "-",
		QueryIP:        "-",
		QueryPort:      "-",
		ResponseIP:     "-",
		ResponsePort:   "-",
		IPDefragmented: false,
		TCPReassembled: false,
	}

	dm.DNSTap = DNSTap{
		Operation:        "-",
		Identity:         "-",
		Version:          "-",
		TimestampRFC3339: "-",
		LatencySec:       "-",
		Extra:            "-",
	}

	dm.DNS = DNS{
		Type:            "-",
		MalformedPacket: false,
		Rcode:           "-",
		Qtype:           "-",
		Qname:           "-",
		DNSRRs:          DNSRRs{Answers: []DNSAnswer{}, Nameservers: []DNSAnswer{}, Records: []DNSAnswer{}},
	}

	dm.EDNS = DNSExtended{
		UDPSize:       0,
		ExtendedRcode: 0,
		Version:       0,
		Do:            0,
		Z:             0,
		Options:       []DNSOption{},
	}
}

func (dm *DNSMessage) handleGeoIPDirectives(directives []string, s *strings.Builder) {
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

func (dm *DNSMessage) handlePdnsDirectives(directives []string, s *strings.Builder) {
	if dm.PowerDNS == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "powerdns-tags":
			if dm.PowerDNS.Tags == nil {
				s.WriteString("-")
			} else {
				if len(dm.PowerDNS.Tags) > 0 {
					if len(directives) == 2 {
						tagIndex, err := strconv.Atoi(directives[1])
						if err != nil {
							log.Fatalf("unsupport tag index provided (integer expected): %s", directives[1])
						}
						if tagIndex >= len(dm.PowerDNS.Tags) {
							s.WriteString("-")
						} else {
							s.WriteString(dm.PowerDNS.Tags[tagIndex])
						}
					} else {
						for i, tag := range dm.PowerDNS.Tags {
							s.WriteString(tag)
							// add separator
							if i+1 < len(dm.PowerDNS.Tags) {
								s.WriteString(",")
							}
						}
					}
				} else {
					s.WriteString("-")
				}
			}
		case directive == "powerdns-applied-policy":
			if len(dm.PowerDNS.AppliedPolicy) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicy)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-original-request-subnet":
			if len(dm.PowerDNS.OriginalRequestSubnet) > 0 {
				s.WriteString(dm.PowerDNS.OriginalRequestSubnet)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-metadata":
			if dm.PowerDNS.Metadata == nil {
				s.WriteString("-")
			} else {
				if len(dm.PowerDNS.Metadata) > 0 && len(directives) == 2 {
					if metaValue, ok := dm.PowerDNS.Metadata[directives[1]]; ok {
						if len(metaValue) > 0 {
							s.WriteString(strings.ReplaceAll(metaValue, " ", "_"))
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

func (dm *DNSMessage) handleSuspiciousDirectives(directives []string, s *strings.Builder) {
	if dm.Suspicious == nil {
		s.WriteString("-")
	} else if directives[0] == "suspicious-score" {
		s.WriteString(strconv.Itoa(int(dm.Suspicious.Score)))
	}
}

func (dm *DNSMessage) handlePublicSuffixDirectives(directives []string, s *strings.Builder) {
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

func (dm *DNSMessage) handleExtractedDirectives(directives []string, s *strings.Builder) {
	if dm.Extracted == nil {
		s.WriteString("-")
		return
	}
	if directives[0] == "extracted-dns-payload" {
		if len(dm.DNS.Payload) > 0 {
			dst := make([]byte, base64.StdEncoding.EncodedLen(len(dm.DNS.Payload)))
			base64.StdEncoding.Encode(dst, dm.DNS.Payload)
			s.Write(dst)
		} else {
			s.WriteString("-")
		}
	}
}

func (dm *DNSMessage) handleFilteringDirectives(directives []string, s *strings.Builder) {
	if dm.Filtering == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "filtering-sample-rate":
			s.WriteString(strconv.Itoa(dm.Filtering.SampleRate))
		default:
			log.Fatalf("unsupport directive for text format: %s", directive)
		}
	}
}

func (dm *DNSMessage) handleReducerDirectives(directives []string, s *strings.Builder) {
	if dm.Reducer == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "reducer-occurences":
			s.WriteString(strconv.Itoa(dm.Reducer.Occurences))
		case directive == "reducer-cumulative-length":
			s.WriteString(strconv.Itoa(dm.Reducer.CumulativeLength))
		}
	}
}

func (dm *DNSMessage) handleMachineLearningDirectives(directives []string, s *strings.Builder) {
	if dm.MachineLearning == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "ml-entropy":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.Entropy, 'f', -1, 64))
		case directive == "ml-length":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Length))
		case directive == "ml-digits":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Digits))
		case directive == "ml-lowers":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Lowers))
		case directive == "ml-uppers":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Uppers))
		case directive == "ml-specials":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Specials))
		case directive == "ml-others":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Others))
		case directive == "ml-labels":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Labels))
		case directive == "ml-ratio-digits":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.RatioDigits, 'f', 3, 64))
		case directive == "ml-ratio-letters":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.RatioLetters, 'f', 3, 64))
		case directive == "ml-ratio-specials":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.RatioSpecials, 'f', 3, 64))
		case directive == "ml-ratio-others":
			s.WriteString(strconv.FormatFloat(dm.MachineLearning.RatioOthers, 'f', 3, 64))
		case directive == "ml-consecutive-chars":
			s.WriteString(strconv.Itoa(dm.MachineLearning.ConsecutiveChars))
		case directive == "ml-consecutive-vowels":
			s.WriteString(strconv.Itoa(dm.MachineLearning.ConsecutiveVowels))
		case directive == "ml-consecutive-digits":
			s.WriteString(strconv.Itoa(dm.MachineLearning.ConsecutiveDigits))
		case directive == "ml-consecutive-consonants":
			s.WriteString(strconv.Itoa(dm.MachineLearning.ConsecutiveConsonants))
		case directive == "ml-size":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Size))
		case directive == "ml-occurences":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Occurences))
		case directive == "ml-uncommon-qtypes":
			s.WriteString(strconv.Itoa(dm.MachineLearning.UncommonQtypes))
		}
	}
}

func (dm *DNSMessage) Bytes(format []string, fieldDelimiter string, fieldBoundary string) []byte {
	var s strings.Builder

	for i, word := range format {
		directives := strings.SplitN(word, ":", 2)
		switch directive := directives[0]; {
		// default directives
		case directive == "ttl":
			if len(dm.DNS.DNSRRs.Answers) > 0 {
				s.WriteString(strconv.Itoa(dm.DNS.DNSRRs.Answers[0].TTL))
			} else {
				s.WriteByte('-')
			}
		case directive == "answer":
			if len(dm.DNS.DNSRRs.Answers) > 0 {
				s.WriteString(dm.DNS.DNSRRs.Answers[0].Rdata)
			} else {
				s.WriteByte('-')
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
				s.WriteByte('-')
			}
		case directive == "answercount":
			s.WriteString(strconv.Itoa(len(dm.DNS.DNSRRs.Answers)))
		case directive == "id":
			s.WriteString(strconv.Itoa(dm.DNS.ID))
		case directive == "timestamp-rfc3339ns", directive == "timestamp":
			s.WriteString(dm.DNSTap.TimestampRFC3339)
		case directive == "timestamp-unixms":
			s.WriteString(fmt.Sprintf("%d", dm.DNSTap.Timestamp/1000000))
		case directive == "timestamp-unixus":
			s.WriteString(fmt.Sprintf("%d", dm.DNSTap.Timestamp/1000))
		case directive == "timestamp-unixns":
			s.WriteString(fmt.Sprintf("%d", dm.DNSTap.Timestamp))
		case directive == "localtime":
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			s.WriteString(ts.Format("2006-01-02 15:04:05.999999999"))
		case directive == "identity":
			s.WriteString(dm.DNSTap.Identity)
		case directive == "version":
			s.WriteString(dm.DNSTap.Version)
		case directive == "extra":
			s.WriteString(dm.DNSTap.Extra)
		case directive == "operation":
			s.WriteString(dm.DNSTap.Operation)
		case directive == "rcode":
			s.WriteString(dm.DNS.Rcode)
		case directive == "queryip":
			s.WriteString(dm.NetworkInfo.QueryIP)
		case directive == "queryport":
			s.WriteString(dm.NetworkInfo.QueryPort)
		case directive == "responseip":
			s.WriteString(dm.NetworkInfo.ResponseIP)
		case directive == "responseport":
			s.WriteString(dm.NetworkInfo.ResponsePort)
		case directive == "family":
			s.WriteString(dm.NetworkInfo.Family)
		case directive == "protocol":
			s.WriteString(dm.NetworkInfo.Protocol)
		case directive == "length-unit":
			s.WriteString(strconv.Itoa(dm.DNS.Length) + "b")
		case directive == "length":
			s.WriteString(strconv.Itoa(dm.DNS.Length))
		case directive == "qname":
			if len(dm.DNS.Qname) == 0 {
				s.WriteString(".")
			} else {
				if strings.Contains(dm.DNS.Qname, fieldDelimiter) {
					qname := dm.DNS.Qname
					if strings.Contains(qname, fieldBoundary) {
						qname = strings.ReplaceAll(qname, fieldBoundary, "\\"+fieldBoundary)
					}
					s.WriteString(fmt.Sprintf(fieldBoundary+"%s"+fieldBoundary, qname))
				} else {
					s.WriteString(dm.DNS.Qname)
				}
			}
		case directive == "qtype":
			s.WriteString(dm.DNS.Qtype)
		case directive == "latency":
			s.WriteString(dm.DNSTap.LatencySec)
		case directive == "malformed":
			if dm.DNS.MalformedPacket {
				s.WriteString("PKTERR")
			} else {
				s.WriteByte('-')
			}
		case directive == "qr":
			s.WriteString(dm.DNS.Type)
		case directive == "opcode":
			s.WriteString(strconv.Itoa(dm.DNS.Opcode))
		case directive == "tr":
			if dm.NetworkInfo.TCPReassembled {
				s.WriteString("TR")
			} else {
				s.WriteByte('-')
			}
		case directive == "df":
			if dm.NetworkInfo.IPDefragmented {
				s.WriteString("DF")
			} else {
				s.WriteByte('-')
			}
		case directive == "tc":
			if dm.DNS.Flags.TC {
				s.WriteString("TC")
			} else {
				s.WriteByte('-')
			}
		case directive == "aa":
			if dm.DNS.Flags.AA {
				s.WriteString("AA")
			} else {
				s.WriteByte('-')
			}
		case directive == "ra":
			if dm.DNS.Flags.RA {
				s.WriteString("RA")
			} else {
				s.WriteByte('-')
			}
		case directive == "ad":
			if dm.DNS.Flags.AD {
				s.WriteString("AD")
			} else {
				s.WriteByte('-')
			}
		// more directives from collectors
		case PdnsDirectives.MatchString(directive):
			dm.handlePdnsDirectives(directives, &s)

		// more directives from transformers
		case ReducerDirectives.MatchString(directive):
			dm.handleReducerDirectives(directives, &s)
		case GeoIPDirectives.MatchString(directive):
			dm.handleGeoIPDirectives(directives, &s)
		case SuspiciousDirectives.MatchString(directive):
			dm.handleSuspiciousDirectives(directives, &s)
		case PublicSuffixDirectives.MatchString(directive):
			dm.handlePublicSuffixDirectives(directives, &s)
		case ExtractedDirectives.MatchString(directive):
			dm.handleExtractedDirectives(directives, &s)
		case MachineLearningDirectives.MatchString(directive):
			dm.handleMachineLearningDirectives(directives, &s)
		case FilteringDirectives.MatchString(directive):
			dm.handleFilteringDirectives(directives, &s)

		// error unsupport directive for text format
		default:
			log.Fatalf("unsupport directive for text format: %s", word)
		}

		if i < len(format)-1 {
			s.WriteString(fieldDelimiter)
		}
	}

	return []byte(s.String())
}

func (dm *DNSMessage) String(format []string, fieldDelimiter string, fieldBoundary string) string {
	return string(dm.Bytes(format, fieldDelimiter, fieldBoundary))
}

func (dm *DNSMessage) ToJSON() string {
	buffer := new(bytes.Buffer)
	json.NewEncoder(buffer).Encode(dm)
	return buffer.String()
}

func (dm *DNSMessage) ToFlatJSON() (string, error) {
	buffer := new(bytes.Buffer)
	flat, err := dm.Flatten()
	if err != nil {
		return "", err
	}
	json.NewEncoder(buffer).Encode(flat)
	return buffer.String(), nil
}

func (dm *DNSMessage) ToDNSTap() ([]byte, error) {
	if len(dm.DNSTap.Payload) > 0 {
		return dm.DNSTap.Payload, nil
	}

	dt := &dnstap.Dnstap{}
	t := dnstap.Dnstap_MESSAGE
	dt.Identity = []byte(dm.DNSTap.Identity)
	dt.Version = []byte("-")
	dt.Type = &t

	mt := dnstap.Message_Type(dnstap.Message_Type_value[dm.DNSTap.Operation])

	var sf dnstap.SocketFamily
	if ipNet, valid := netlib.IPToInet[dm.NetworkInfo.Family]; valid {
		sf = dnstap.SocketFamily(dnstap.SocketFamily_value[ipNet])
	}
	sp := dnstap.SocketProtocol(dnstap.SocketProtocol_value[dm.NetworkInfo.Protocol])
	tsec := uint64(dm.DNSTap.TimeSec)
	tnsec := uint32(dm.DNSTap.TimeNsec)

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

	reqIP := net.ParseIP(dm.NetworkInfo.QueryIP)
	if dm.NetworkInfo.Family == netlib.ProtoIPv4 {
		msg.QueryAddress = reqIP.To4()
	} else {
		msg.QueryAddress = reqIP.To16()
	}
	msg.QueryPort = &qport

	rspIP := net.ParseIP(dm.NetworkInfo.ResponseIP)
	if dm.NetworkInfo.Family == netlib.ProtoIPv4 {
		msg.ResponseAddress = rspIP.To4()
	} else {
		msg.ResponseAddress = rspIP.To16()
	}
	msg.ResponsePort = &rport

	if dm.DNS.Type == DNSQuery {
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

func (dm *DNSMessage) ToPacketLayer() ([]gopacket.SerializableLayer, error) {
	if len(dm.DNS.Payload) == 0 {
		return nil, errors.New("payload is empty")
	}

	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip6 := &layers.IPv6{Version: 6}
	udp := &layers.UDP{}
	tcp := &layers.TCP{}

	// prepare ip
	srcIP, srcPort, dstIP, dstPort := GetIPPort(dm)

	// packet layer array
	pkt := []gopacket.SerializableLayer{}

	// set source and destination IP
	switch dm.NetworkInfo.Family {
	case netlib.ProtoIPv4:
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4.SrcIP = net.ParseIP(srcIP)
		ip4.DstIP = net.ParseIP(dstIP)
	case netlib.ProtoIPv6:
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6.SrcIP = net.ParseIP(srcIP)
		ip6.DstIP = net.ParseIP(dstIP)
	default:
		return nil, errors.New("family (" + dm.NetworkInfo.Family + ") not yet implemented")
	}

	// set transport
	switch dm.NetworkInfo.Protocol {

	// DNS over UDP
	case netlib.ProtoUDP:
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)

		// update iplayer
		switch dm.NetworkInfo.Family {
		case netlib.ProtoIPv4:
			ip4.Protocol = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4)
		case netlib.ProtoIPv6:
			ip6.NextHeader = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6)
		}

	// DNS over TCP
	case netlib.ProtoTCP:
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.PSH = true
		tcp.Window = 65535

		// dns length
		dnsLengthField := make([]byte, 2)
		binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.DNS.Length))

		// update iplayer
		switch dm.NetworkInfo.Family {
		case netlib.ProtoIPv4:
			ip4.Protocol = layers.IPProtocolTCP
			tcp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip4)
		case netlib.ProtoIPv6:
			ip6.NextHeader = layers.IPProtocolTCP
			tcp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip6)
		}

	// DNS over HTTPS and DNS over TLS
	// These protocols are translated to DNS over UDP
	case ProtoDoH, ProtoDoT:
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)

		// update iplayer
		switch dm.NetworkInfo.Family {
		case netlib.ProtoIPv4:
			ip4.Protocol = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4)
		case netlib.ProtoIPv6:
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

func (dm *DNSMessage) Flatten() (ret map[string]interface{}, err error) {
	// TODO perhaps panic when flattening fails, as it should always work.
	var tmp []byte
	if tmp, err = json.Marshal(dm); err != nil {
		return
	}
	json.Unmarshal(tmp, &ret)
	ret, err = flat.Flatten(ret, nil)
	return
}

func GetFakeDNSMessage() DNSMessage {
	dm := DNSMessage{}
	dm.Init()
	dm.DNSTap.Identity = "collector"
	dm.DNSTap.Operation = "CLIENT_QUERY"
	dm.DNS.Type = DNSQuery
	dm.DNS.Qname = "dns.collector"
	dm.NetworkInfo.QueryIP = "1.2.3.4"
	dm.NetworkInfo.QueryPort = "1234"
	dm.NetworkInfo.ResponseIP = "4.3.2.1"
	dm.NetworkInfo.ResponsePort = "4321"
	dm.DNS.Rcode = "NOERROR"
	dm.DNS.Qtype = "A"
	return dm
}

func GetFakeDNSMessageWithPayload() DNSMessage {
	// fake dns query payload
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm := GetFakeDNSMessage()
	dm.NetworkInfo.Family = netlib.ProtoIPv4
	dm.NetworkInfo.Protocol = netlib.ProtoUDP
	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)
	return dm
}
