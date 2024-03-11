package dnsutils

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

var (
	DNSQuery                  = "QUERY"
	DNSQueryQuiet             = "Q"
	DNSReply                  = "REPLY"
	DNSReplyQuiet             = "R"
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
	Name      string `json:"name"`
	Rdatatype string `json:"rdatatype"`
	Class     string `json:"class"`
	TTL       int    `json:"ttl"`
	Rdata     string `json:"rdata"`
}

type DNSFlags struct {
	QR bool `json:"qr"`
	TC bool `json:"tc"`
	AA bool `json:"aa"`
	RA bool `json:"ra"`
	AD bool `json:"ad"`
	RD bool `json:"rd"`
	CD bool `json:"cd"`
}

type DNSNetInfo struct {
	Family         string `json:"family"`
	Protocol       string `json:"protocol"`
	QueryIP        string `json:"query-ip"`
	QueryPort      string `json:"query-port"`
	ResponseIP     string `json:"response-ip"`
	ResponsePort   string `json:"response-port"`
	IPDefragmented bool   `json:"ip-defragmented"`
	TCPReassembled bool   `json:"tcp-reassembled"`
}

type DNSRRs struct {
	Answers     []DNSAnswer `json:"an"`
	Nameservers []DNSAnswer `json:"ns"`
	Records     []DNSAnswer `json:"ar"`
}

type DNS struct {
	Type    string `json:"-"`
	Payload []byte `json:"-"`
	Length  int    `json:"length"`
	ID      int    `json:"id"`
	Opcode  int    `json:"opcode"`
	Rcode   string `json:"rcode"`
	Qname   string `json:"qname"`
	Qclass  string `json:"qclass"`

	Qtype           string   `json:"qtype"`
	Flags           DNSFlags `json:"flags"`
	DNSRRs          DNSRRs   `json:"resource-records"`
	MalformedPacket bool     `json:"malformed-packet"`
}

type DNSOption struct {
	Code int    `json:"code"`
	Name string `json:"name"`
	Data string `json:"data"`
}

type DNSExtended struct {
	UDPSize       int         `json:"udp-size"`
	ExtendedRcode int         `json:"rcode"`
	Version       int         `json:"version"`
	Do            int         `json:"dnssec-ok"`
	Z             int         `json:"-"`
	Options       []DNSOption `json:"options"`
}

type DNSTap struct {
	Operation        string  `json:"operation"`
	Identity         string  `json:"identity"`
	Version          string  `json:"version"`
	TimestampRFC3339 string  `json:"timestamp-rfc3339ns"`
	Timestamp        int64   `json:"-"`
	TimeSec          int     `json:"-"`
	TimeNsec         int     `json:"-"`
	Latency          float64 `json:"-"`
	LatencySec       string  `json:"latency"`
	Payload          []byte  `json:"-"`
	Extra            string  `json:"extra"`
	PolicyRule       string  `json:"policy-rule"`
	PolicyType       string  `json:"policy-type"`
	PolicyMatch      string  `json:"policy-match"`
	PolicyAction     string  `json:"policy-action"`
	PolicyValue      string  `json:"policy-value"`
	PeerName         string  `json:"peer-name"`
	QueryZone        string  `json:"query-zone"`
}

type PowerDNS struct {
	Tags                  []string          `json:"tags"`
	OriginalRequestSubnet string            `json:"original-request-subnet"`
	AppliedPolicy         string            `json:"applied-policy"`
	AppliedPolicyHit      string            `json:"applied-policy-hit"`
	AppliedPolicyKind     string            `json:"applied-policy-kind"`
	AppliedPolicyTrigger  string            `json:"applied-policy-trigger"`
	AppliedPolicyType     string            `json:"applied-policy-type"`
	Metadata              map[string]string `json:"metadata"`
	HTTPVersion           string            `json:"http-version"`
}

type TransformDNSGeo struct {
	City                   string `json:"city"`
	Continent              string `json:"continent"`
	CountryIsoCode         string `json:"country-isocode"`
	AutonomousSystemNumber string `json:"as-number"`
	AutonomousSystemOrg    string `json:"as-owner"`
}

type TransformSuspicious struct {
	Score                 float64 `json:"score"`
	MalformedPacket       bool    `json:"malformed-pkt"`
	LargePacket           bool    `json:"large-pkt"`
	LongDomain            bool    `json:"long-domain"`
	SlowDomain            bool    `json:"slow-domain"`
	UnallowedChars        bool    `json:"unallowed-chars"`
	UncommonQtypes        bool    `json:"uncommon-qtypes"`
	ExcessiveNumberLabels bool    `json:"excessive-number-labels"`
	Domain                string  `json:"domain,omitempty"`
}

type TransformPublicSuffix struct {
	QnamePublicSuffix        string `json:"tld"`
	QnameEffectiveTLDPlusOne string `json:"etld+1"`
	ManagedByICANN           bool   `json:"managed-icann"`
}

type TransformExtracted struct {
	Base64Payload []byte `json:"dns_payload"`
}

type TransformReducer struct {
	Occurrences      int `json:"occurrences"`
	CumulativeLength int `json:"cumulative-length"`
}

type TransformFiltering struct {
	SampleRate int `json:"sample-rate"`
}

type TransformML struct {
	Entropy               float64 `json:"entropy"`  // Entropy of query name
	Length                int     `json:"length"`   // Length of domain
	Labels                int     `json:"labels"`   // Number of labels in the query name  separated by dots
	Digits                int     `json:"digits"`   // Count of numerical characters
	Lowers                int     `json:"lowers"`   // Count of lowercase characters
	Uppers                int     `json:"uppers"`   // Count of uppercase characters
	Specials              int     `json:"specials"` // Number of special characters; special characters such as dash, underscore, equal sign,...
	Others                int     `json:"others"`
	RatioDigits           float64 `json:"ratio-digits"`
	RatioLetters          float64 `json:"ratio-letters"`
	RatioSpecials         float64 `json:"ratio-specials"`
	RatioOthers           float64 `json:"ratio-others"`
	ConsecutiveChars      int     `json:"consecutive-chars"`
	ConsecutiveVowels     int     `json:"consecutive-vowels"`
	ConsecutiveDigits     int     `json:"consecutive-digits"`
	ConsecutiveConsonants int     `json:"consecutive-consonants"`
	Size                  int     `json:"size"`
	Occurrences           int     `json:"occurrences"`
	UncommonQtypes        int     `json:"uncommon-qtypes"`
}

type TransformATags struct {
	Tags []string `json:"tags"`
}

type RelabelingRule struct {
	Regex       *regexp.Regexp
	Replacement string
	Action      string
}

type TransformRelabeling struct {
	Rules []RelabelingRule
}

type DNSMessage struct {
	NetworkInfo     DNSNetInfo             `json:"network"`
	DNS             DNS                    `json:"dns"`
	EDNS            DNSExtended            `json:"edns"`
	DNSTap          DNSTap                 `json:"dnstap"`
	Geo             *TransformDNSGeo       `json:"geoip,omitempty"`
	PowerDNS        *PowerDNS              `json:"powerdns,omitempty"`
	Suspicious      *TransformSuspicious   `json:"suspicious,omitempty"`
	PublicSuffix    *TransformPublicSuffix `json:"publicsuffix,omitempty"`
	Extracted       *TransformExtracted    `json:"extracted,omitempty"`
	Reducer         *TransformReducer      `json:"reducer,omitempty"`
	MachineLearning *TransformML           `json:"ml,omitempty"`
	Filtering       *TransformFiltering    `json:"filtering,omitempty"`
	ATags           *TransformATags        `json:"atags,omitempty"`
	Relabeling      *TransformRelabeling   `json:"-"`
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
		PolicyRule:       "-",
		PolicyType:       "-",
		PolicyMatch:      "-",
		PolicyAction:     "-",
		PolicyValue:      "-",
		PeerName:         "-",
		QueryZone:        "-",
	}

	dm.DNS = DNS{
		ID:              0,
		Type:            "-",
		MalformedPacket: false,
		Rcode:           "-",
		Qtype:           "-",
		Qname:           "-",
		Qclass:          "-",
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

func (dm *DNSMessage) InitTransforms() {
	dm.ATags = &TransformATags{}
	dm.Filtering = &TransformFiltering{}
	dm.MachineLearning = &TransformML{}
	dm.Reducer = &TransformReducer{}
	dm.Extracted = &TransformExtracted{}
	dm.PublicSuffix = &TransformPublicSuffix{}
	dm.Suspicious = &TransformSuspicious{}
	dm.PowerDNS = &PowerDNS{}
	dm.Geo = &TransformDNSGeo{}
	dm.Relabeling = &TransformRelabeling{}
}

func (dm *DNSMessage) handleGeoIPDirectives(directive string, s *strings.Builder) error {
	if dm.Geo == nil {
		s.WriteString("-")
	} else {
		switch {
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
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handlePdnsDirectives(directive string, s *strings.Builder) error {
	if dm.PowerDNS == nil {
		s.WriteString("-")
	} else {
		var directives []string
		if i := strings.IndexByte(directive, ':'); i == -1 {
			directives = append(directives, directive)
		} else {
			directives = []string{directive[:i], directive[i+1:]}
		}

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
		case directive == "powerdns-applied-policy-hit":
			if len(dm.PowerDNS.AppliedPolicyHit) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicyHit)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-applied-policy-kind":
			if len(dm.PowerDNS.AppliedPolicyKind) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicyKind)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-applied-policy-trigger":
			if len(dm.PowerDNS.AppliedPolicyTrigger) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicyTrigger)
			} else {
				s.WriteString("-")
			}
		case directive == "powerdns-applied-policy-type":
			if len(dm.PowerDNS.AppliedPolicyType) > 0 {
				s.WriteString(dm.PowerDNS.AppliedPolicyType)
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
		case directive == "powerdns-http-version":
			if len(dm.PowerDNS.HTTPVersion) > 0 {
				s.WriteString(dm.PowerDNS.HTTPVersion)
			} else {
				s.WriteString("-")
			}
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleSuspiciousDirectives(directive string, s *strings.Builder) error {
	if dm.Suspicious == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "suspicious-score":
			s.WriteString(strconv.Itoa(int(dm.Suspicious.Score)))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handlePublicSuffixDirectives(directive string, s *strings.Builder) error {
	if dm.PublicSuffix == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "publixsuffix-tld":
			s.WriteString(dm.PublicSuffix.QnamePublicSuffix)
		case directive == "publixsuffix-etld+1":
			s.WriteString(dm.PublicSuffix.QnameEffectiveTLDPlusOne)
		case directive == "publixsuffix-managed-icann":
			if dm.PublicSuffix.ManagedByICANN {
				s.WriteString("managed")
			} else {
				s.WriteString("private")
			}
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleExtractedDirectives(directive string, s *strings.Builder) error {
	if dm.Extracted == nil {
		s.WriteString("-")
		return nil
	}
	switch {
	case directive == "extracted-dns-payload":
		if len(dm.DNS.Payload) > 0 {
			dst := make([]byte, base64.StdEncoding.EncodedLen(len(dm.DNS.Payload)))
			base64.StdEncoding.Encode(dst, dm.DNS.Payload)
			s.Write(dst)
		} else {
			s.WriteString("-")
		}
	default:
		return errors.New(ErrorUnexpectedDirective + directive)
	}
	return nil
}

func (dm *DNSMessage) handleFilteringDirectives(directive string, s *strings.Builder) error {
	if dm.Filtering == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "filtering-sample-rate":
			s.WriteString(strconv.Itoa(dm.Filtering.SampleRate))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleReducerDirectives(directive string, s *strings.Builder) error {
	if dm.Reducer == nil {
		s.WriteString("-")
	} else {
		switch {
		case directive == "reducer-occurrences":
			s.WriteString(strconv.Itoa(dm.Reducer.Occurrences))
		case directive == "reducer-cumulative-length":
			s.WriteString(strconv.Itoa(dm.Reducer.CumulativeLength))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleMachineLearningDirectives(directive string, s *strings.Builder) error {
	if dm.MachineLearning == nil {
		s.WriteString("-")
	} else {
		switch {
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
		case directive == "ml-occurrences":
			s.WriteString(strconv.Itoa(dm.MachineLearning.Occurrences))
		case directive == "ml-uncommon-qtypes":
			s.WriteString(strconv.Itoa(dm.MachineLearning.UncommonQtypes))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) Bytes(format []string, fieldDelimiter string, fieldBoundary string) []byte {
	line, err := dm.ToTextLine(format, fieldDelimiter, fieldBoundary)
	if err != nil {
		log.Fatalf("unsupport directive for text format: %s", err)
	}
	return line
}

func (dm *DNSMessage) String(format []string, fieldDelimiter string, fieldBoundary string) string {
	return string(dm.Bytes(format, fieldDelimiter, fieldBoundary))
}

func (dm *DNSMessage) ToTextLine(format []string, fieldDelimiter string, fieldBoundary string) ([]byte, error) {
	var s strings.Builder

	answers := dm.DNS.DNSRRs.Answers
	qname := dm.DNS.Qname
	flags := dm.DNS.Flags

	for i, directive := range format {
		switch {
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
		case directive == "qname":
			if len(qname) == 0 {
				s.WriteString(".")
			} else {
				if strings.Contains(qname, fieldDelimiter) {
					qnameEscaped := qname
					if strings.Contains(qname, fieldBoundary) {
						qnameEscaped = strings.ReplaceAll(qnameEscaped, fieldBoundary, "\\"+fieldBoundary)
					}
					s.WriteString(fmt.Sprintf(fieldBoundary+"%s"+fieldBoundary, qnameEscaped))
				} else {
					s.WriteString(qname)
				}
			}
		case directive == "identity":
			s.WriteString(dm.DNSTap.Identity)
		case directive == "peer-name":
			s.WriteString(dm.DNSTap.PeerName)
		case directive == "version":
			s.WriteString(dm.DNSTap.Version)
		case directive == "extra":
			s.WriteString(dm.DNSTap.Extra)
		case directive == "policy-rule":
			s.WriteString(dm.DNSTap.PolicyRule)
		case directive == "policy-type":
			s.WriteString(dm.DNSTap.PolicyType)
		case directive == "policy-action":
			s.WriteString(dm.DNSTap.PolicyAction)
		case directive == "policy-match":
			s.WriteString(dm.DNSTap.PolicyMatch)
		case directive == "policy-value":
			s.WriteString(dm.DNSTap.PolicyValue)
		case directive == "query-zone":
			s.WriteString(dm.DNSTap.QueryZone)
		case directive == "operation":
			s.WriteString(dm.DNSTap.Operation)
		case directive == "rcode":
			s.WriteString(dm.DNS.Rcode)

		case directive == "id":
			s.WriteString(strconv.Itoa(dm.DNS.ID))
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
		case directive == "qtype":
			s.WriteString(dm.DNS.Qtype)
		case directive == "qclass":
			s.WriteString(dm.DNS.Qclass)
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
			if flags.TC {
				s.WriteString("TC")
			} else {
				s.WriteByte('-')
			}
		case directive == "aa":
			if flags.AA {
				s.WriteString("AA")
			} else {
				s.WriteByte('-')
			}
		case directive == "ra":
			if flags.RA {
				s.WriteString("RA")
			} else {
				s.WriteByte('-')
			}
		case directive == "ad":
			if flags.AD {
				s.WriteString("AD")
			} else {
				s.WriteByte('-')
			}
		case directive == "ttl":
			if len(answers) > 0 {
				s.WriteString(strconv.Itoa(answers[0].TTL))
			} else {
				s.WriteByte('-')
			}
		case directive == "answer":
			if len(answers) > 0 {
				s.WriteString(answers[0].Rdata)
			} else {
				s.WriteByte('-')
			}
		case directive == "answercount":
			s.WriteString(strconv.Itoa(len(answers)))

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

		// more directives from collectors
		case PdnsDirectives.MatchString(directive):
			err := dm.handlePdnsDirectives(directive, &s)
			if err != nil {
				return nil, err
			}

		// more directives from transformers
		case ReducerDirectives.MatchString(directive):
			err := dm.handleReducerDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case GeoIPDirectives.MatchString(directive):
			err := dm.handleGeoIPDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case SuspiciousDirectives.MatchString(directive):
			err := dm.handleSuspiciousDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case PublicSuffixDirectives.MatchString(directive):
			err := dm.handlePublicSuffixDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case ExtractedDirectives.MatchString(directive):
			err := dm.handleExtractedDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case MachineLearningDirectives.MatchString(directive):
			err := dm.handleMachineLearningDirectives(directive, &s)
			if err != nil {
				return nil, err
			}
		case FilteringDirectives.MatchString(directive):
			err := dm.handleFilteringDirectives(directive, &s)
			if err != nil {
				return nil, err
			}

		// handle invalid directive
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

		if i < len(format)-1 {
			s.WriteString(fieldDelimiter)
		}
	}
	return []byte(s.String()), nil
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

func (dm *DNSMessage) ToDNSTap(extended bool) ([]byte, error) {
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
		} else if port < 0 || port > 65535 {
			return nil, errors.New("invalid response port value")
		} else {
			rport = uint32(port)
		}
	}

	if dm.NetworkInfo.QueryPort != "-" {
		if port, err := strconv.Atoi(dm.NetworkInfo.QueryPort); err != nil {
			return nil, err
		} else if port < 0 || port > 65535 {
			return nil, errors.New("invalid query port value")
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

	// add dnstap extra
	if len(dm.DNSTap.Extra) > 0 {
		dt.Extra = []byte(dm.DNSTap.Extra)
	}

	// contruct new dnstap field with all tranformations
	// the original extra field is kept if exist
	if extended {
		ednstap := &ExtendedDnstap{}

		// add original dnstap value if exist
		if len(dm.DNSTap.Extra) > 0 {
			ednstap.OriginalDnstapExtra = []byte(dm.DNSTap.Extra)
		}

		// add additionnals tags ?
		if dm.ATags != nil {
			ednstap.Atags = &ExtendedATags{
				Tags: dm.ATags.Tags,
			}
		}

		// add public suffix
		if dm.PublicSuffix != nil {
			ednstap.Normalize = &ExtendedNormalize{
				Tld:         dm.PublicSuffix.QnamePublicSuffix,
				EtldPlusOne: dm.PublicSuffix.QnameEffectiveTLDPlusOne,
			}
		}

		// add filtering
		if dm.Filtering != nil {
			ednstap.Filtering = &ExtendedFiltering{
				SampleRate: uint32(dm.Filtering.SampleRate),
			}
		}

		// add geo
		if dm.Geo != nil {
			ednstap.Geo = &ExtendedGeo{
				City:      dm.Geo.City,
				Continent: dm.Geo.Continent,
				Isocode:   dm.Geo.CountryIsoCode,
				AsNumber:  dm.Geo.AutonomousSystemNumber,
				AsOrg:     dm.Geo.AutonomousSystemOrg,
			}
		}

		extendedData, err := proto.Marshal(ednstap)
		if err != nil {
			return nil, err
		}
		dt.Extra = extendedData
	}

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
	if srcPort < 0 || srcPort > math.MaxUint16 {
		return nil, errors.New("invalid source port value")
	}
	if dstPort < 0 || dstPort > math.MaxUint16 {
		return nil, errors.New("invalid destination port value")
	}

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

func (dm *DNSMessage) Flatten() (map[string]interface{}, error) {
	dnsFields := map[string]interface{}{
		"dns.flags.aa":               dm.DNS.Flags.AA,
		"dns.flags.ad":               dm.DNS.Flags.AD,
		"dns.flags.qr":               dm.DNS.Flags.QR,
		"dns.flags.ra":               dm.DNS.Flags.RA,
		"dns.flags.tc":               dm.DNS.Flags.TC,
		"dns.flags.rd":               dm.DNS.Flags.RD,
		"dns.flags.cd":               dm.DNS.Flags.CD,
		"dns.length":                 dm.DNS.Length,
		"dns.malformed-packet":       dm.DNS.MalformedPacket,
		"dns.id":                     dm.DNS.ID,
		"dns.opcode":                 dm.DNS.Opcode,
		"dns.qname":                  dm.DNS.Qname,
		"dns.qtype":                  dm.DNS.Qtype,
		"dns.qclass":                 dm.DNS.Qclass,
		"dns.rcode":                  dm.DNS.Rcode,
		"dnstap.identity":            dm.DNSTap.Identity,
		"dnstap.latency":             dm.DNSTap.LatencySec,
		"dnstap.operation":           dm.DNSTap.Operation,
		"dnstap.timestamp-rfc3339ns": dm.DNSTap.TimestampRFC3339,
		"dnstap.version":             dm.DNSTap.Version,
		"dnstap.extra":               dm.DNSTap.Extra,
		"dnstap.policy-rule":         dm.DNSTap.PolicyRule,
		"dnstap.policy-type":         dm.DNSTap.PolicyType,
		"dnstap.policy-action":       dm.DNSTap.PolicyAction,
		"dnstap.policy-match":        dm.DNSTap.PolicyMatch,
		"dnstap.policy-value":        dm.DNSTap.PolicyValue,
		"dnstap.peer-name":           dm.DNSTap.PeerName,
		"dnstap.query-zone":          dm.DNSTap.QueryZone,
		"edns.dnssec-ok":             dm.EDNS.Do,
		"edns.rcode":                 dm.EDNS.ExtendedRcode,
		"edns.udp-size":              dm.EDNS.UDPSize,
		"edns.version":               dm.EDNS.Version,
		"network.family":             dm.NetworkInfo.Family,
		"network.ip-defragmented":    dm.NetworkInfo.IPDefragmented,
		"network.protocol":           dm.NetworkInfo.Protocol,
		"network.query-ip":           dm.NetworkInfo.QueryIP,
		"network.query-port":         dm.NetworkInfo.QueryPort,
		"network.response-ip":        dm.NetworkInfo.ResponseIP,
		"network.response-port":      dm.NetworkInfo.ResponsePort,
		"network.tcp-reassembled":    dm.NetworkInfo.TCPReassembled,
	}

	// Add empty slices
	if len(dm.DNS.DNSRRs.Answers) == 0 {
		dnsFields["dns.resource-records.an"] = "-"
	}
	if len(dm.DNS.DNSRRs.Records) == 0 {
		dnsFields["dns.resource-records.ar"] = "-"
	}
	if len(dm.DNS.DNSRRs.Nameservers) == 0 {
		dnsFields["dns.resource-records.ns"] = "-"
	}
	if len(dm.EDNS.Options) == 0 {
		dnsFields["edns.options"] = "-"
	}

	// Add DNSAnswer fields: "dns.resource-records.an.0.name": "google.nl"
	// nolint: goconst
	for i, an := range dm.DNS.DNSRRs.Answers {
		prefixAn := "dns.resource-records.an." + strconv.Itoa(i)
		dnsFields[prefixAn+".name"] = an.Name
		dnsFields[prefixAn+".rdata"] = an.Rdata
		dnsFields[prefixAn+".rdatatype"] = an.Rdatatype
		dnsFields[prefixAn+".ttl"] = an.TTL
		dnsFields[prefixAn+".class"] = an.Class
	}
	for i, ns := range dm.DNS.DNSRRs.Nameservers {
		prefixNs := "dns.resource-records.ns." + strconv.Itoa(i)
		dnsFields[prefixNs+".name"] = ns.Name
		dnsFields[prefixNs+".rdata"] = ns.Rdata
		dnsFields[prefixNs+".rdatatype"] = ns.Rdatatype
		dnsFields[prefixNs+".ttl"] = ns.TTL
		dnsFields[prefixNs+".class"] = ns.Class
	}
	for i, ar := range dm.DNS.DNSRRs.Records {
		prefixAr := "dns.resource-records.ar." + strconv.Itoa(i)
		dnsFields[prefixAr+".name"] = ar.Name
		dnsFields[prefixAr+".rdata"] = ar.Rdata
		dnsFields[prefixAr+".rdatatype"] = ar.Rdatatype
		dnsFields[prefixAr+".ttl"] = ar.TTL
		dnsFields[prefixAr+".class"] = ar.Class
	}

	// Add EDNSoptions fields: "edns.options.0.code": 10,
	for i, opt := range dm.EDNS.Options {
		prefixOpt := "edns.options." + strconv.Itoa(i)
		dnsFields[prefixOpt+".code"] = opt.Code
		dnsFields[prefixOpt+".data"] = opt.Data
		dnsFields[prefixOpt+".name"] = opt.Name
	}

	// Add TransformDNSGeo fields
	if dm.Geo != nil {
		dnsFields["geoip.city"] = dm.Geo.City
		dnsFields["geoip.continent"] = dm.Geo.Continent
		dnsFields["geoip.country-isocode"] = dm.Geo.CountryIsoCode
		dnsFields["geoip.as-number"] = dm.Geo.AutonomousSystemNumber
		dnsFields["geoip.as-owner"] = dm.Geo.AutonomousSystemOrg
	}

	// Add TransformSuspicious fields
	if dm.Suspicious != nil {
		dnsFields["suspicious.score"] = dm.Suspicious.Score
		dnsFields["suspicious.malformed-pkt"] = dm.Suspicious.MalformedPacket
		dnsFields["suspicious.large-pkt"] = dm.Suspicious.LargePacket
		dnsFields["suspicious.long-domain"] = dm.Suspicious.LongDomain
		dnsFields["suspicious.slow-domain"] = dm.Suspicious.SlowDomain
		dnsFields["suspicious.unallowed-chars"] = dm.Suspicious.UnallowedChars
		dnsFields["suspicious.uncommon-qtypes"] = dm.Suspicious.UncommonQtypes
		dnsFields["suspicious.excessive-number-labels"] = dm.Suspicious.ExcessiveNumberLabels
		dnsFields["suspicious.domain"] = dm.Suspicious.Domain
	}

	// Add TransformPublicSuffix fields
	if dm.PublicSuffix != nil {
		dnsFields["publicsuffix.tld"] = dm.PublicSuffix.QnamePublicSuffix
		dnsFields["publicsuffix.etld+1"] = dm.PublicSuffix.QnameEffectiveTLDPlusOne
		dnsFields["publicsuffix.managed-icann"] = dm.PublicSuffix.ManagedByICANN
	}

	// Add TransformExtracted fields
	if dm.Extracted != nil {
		dnsFields["extracted.dns_payload"] = dm.Extracted.Base64Payload
	}

	// Add TransformReducer fields
	if dm.Reducer != nil {
		dnsFields["reducer.occurrences"] = dm.Reducer.Occurrences
		dnsFields["reducer.cumulative-length"] = dm.Reducer.CumulativeLength
	}

	// Add TransformFiltering fields
	if dm.Filtering != nil {
		dnsFields["filtering.sample-rate"] = dm.Filtering.SampleRate
	}

	// Add TransformML fields
	if dm.MachineLearning != nil {
		dnsFields["ml.entropy"] = dm.MachineLearning.Entropy
		dnsFields["ml.length"] = dm.MachineLearning.Length
		dnsFields["ml.labels"] = dm.MachineLearning.Labels
		dnsFields["ml.digits"] = dm.MachineLearning.Digits
		dnsFields["ml.lowers"] = dm.MachineLearning.Lowers
		dnsFields["ml.uppers"] = dm.MachineLearning.Uppers
		dnsFields["ml.specials"] = dm.MachineLearning.Specials
		dnsFields["ml.others"] = dm.MachineLearning.Others
		dnsFields["ml.ratio-digits"] = dm.MachineLearning.RatioDigits
		dnsFields["ml.ratio-letters"] = dm.MachineLearning.RatioLetters
		dnsFields["ml.ratio-specials"] = dm.MachineLearning.RatioSpecials
		dnsFields["ml.ratio-others"] = dm.MachineLearning.RatioOthers
		dnsFields["ml.consecutive-chars"] = dm.MachineLearning.ConsecutiveChars
		dnsFields["ml.consecutive-vowels"] = dm.MachineLearning.ConsecutiveVowels
		dnsFields["ml.consecutive-digits"] = dm.MachineLearning.ConsecutiveDigits
		dnsFields["ml.consecutive-consonants"] = dm.MachineLearning.ConsecutiveConsonants
		dnsFields["ml.size"] = dm.MachineLearning.Size
		dnsFields["ml.occurrences"] = dm.MachineLearning.Occurrences
		dnsFields["ml.uncommon-qtypes"] = dm.MachineLearning.UncommonQtypes
	}

	// Add TransformATags fields
	if dm.ATags != nil {
		if len(dm.ATags.Tags) == 0 {
			dnsFields["atags.tags"] = "-"
		}
		for i, tag := range dm.ATags.Tags {
			dnsFields["atags.tags."+strconv.Itoa(i)] = tag
		}
	}

	// Add PowerDNS collectors fields
	if dm.PowerDNS != nil {
		if len(dm.PowerDNS.Tags) == 0 {
			dnsFields["powerdns.tags"] = "-"
		}
		for i, tag := range dm.PowerDNS.Tags {
			dnsFields["powerdns.tags."+strconv.Itoa(i)] = tag
		}
		dnsFields["powerdns.original-request-subnet"] = dm.PowerDNS.OriginalRequestSubnet
		dnsFields["powerdns.applied-policy"] = dm.PowerDNS.AppliedPolicy
		dnsFields["powerdns.applied-policy-hit"] = dm.PowerDNS.AppliedPolicyHit
		dnsFields["powerdns.applied-policy-kind"] = dm.PowerDNS.AppliedPolicyKind
		dnsFields["powerdns.applied-policy-trigger"] = dm.PowerDNS.AppliedPolicyTrigger
		dnsFields["powerdns.applied-policy-type"] = dm.PowerDNS.AppliedPolicyType
		for mk, mv := range dm.PowerDNS.Metadata {
			dnsFields["powerdns.metadata."+mk] = mv
		}
		dnsFields["powerdns.http-version"] = dm.PowerDNS.HTTPVersion
	}

	// relabeling ?
	if dm.Relabeling != nil {
		err := dm.ApplyRelabeling(dnsFields)
		if err != nil {
			return nil, err
		}
	}

	return dnsFields, nil
}

func (dm *DNSMessage) ApplyRelabeling(dnsFields map[string]interface{}) error {

	for _, label := range dm.Relabeling.Rules {
		regex := label.Regex
		for key := range dnsFields {
			if regex.MatchString(key) {
				if label.Action == "rename" {
					replacement := label.Replacement
					if value, exists := dnsFields[replacement]; exists {
						switch v := value.(type) {
						case []string:
							dnsFields[replacement] = append(v, convertToString(dnsFields[key]))
						default:
							dnsFields[replacement] = []string{convertToString(v), convertToString(dnsFields[key])}
						}
					} else {
						dnsFields[replacement] = convertToString(dnsFields[key])
					}
				}

				// delete on all case
				delete(dnsFields, key)
			}
		}
	}

	return nil
}

func (dm *DNSMessage) Matching(matching map[string]interface{}) (error, bool) {
	if len(matching) == 0 {
		return nil, false
	}

	dmValue := reflect.ValueOf(dm)

	if dmValue.Kind() == reflect.Ptr {
		dmValue = dmValue.Elem()
	}

	var isMatch = true

	for nestedKeys, value := range matching {
		realValue, found := getFieldByJSONTag(dmValue, nestedKeys)
		if !found {
			return nil, false
		}

		expectedValue := reflect.ValueOf(value)
		// fmt.Println(nestedKeys, realValue, realValue.Kind(), expectedValue.Kind())

		switch expectedValue.Kind() {
		// integer
		case reflect.Int:
			if match, _ := matchUserInteger(realValue, expectedValue); !match {
				return nil, false
			}

		// string
		case reflect.String:
			if match, _ := matchUserPattern(realValue, expectedValue); !match {
				return nil, false
			}

		// bool
		case reflect.Bool:
			if match, _ := matchUserBoolean(realValue, expectedValue); !match {
				return nil, false
			}

		// map
		case reflect.Map:
			if match, _ := matchUserMap(realValue, expectedValue); !match {
				return nil, false
			}

		// list/slice
		case reflect.Slice:
			if match, _ := matchUserSlice(realValue, expectedValue); !match {
				return nil, false
			}

		// other user types
		default:
			return fmt.Errorf("unsupported type value: %s", expectedValue.Kind()), false
		}

	}

	return nil, isMatch
}

// map can be provided by user in the config
// dns.qname:
// match-source: "file://./testsdata/filtering_keep_domains_regex.txt"
// source-kind: "regexp_list"
func matchUserMap(realValue, expectedValue reflect.Value) (bool, error) {
	for _, opKey := range expectedValue.MapKeys() {
		opValue := expectedValue.MapIndex(opKey)
		opName := opKey.Interface().(string)

		switch opName {
		// Integer great than ?
		case MatchingOpGreaterThan:
			if _, ok := opValue.Interface().(int); !ok {
				return false, fmt.Errorf("integer is expected for greater-than operator")
			}

			// If realValue is a slice
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)

					// Check if the element is a int
					if _, ok := elemValue.Interface().(int); !ok {
						continue
					}

					// Check for match
					if elemValue.Interface().(int) > opValue.Interface().(int) {
						return true, nil
					}
				}
				return false, nil
			}

			if realValue.Kind() != reflect.Int {
				return false, nil
			}
			if realValue.Interface().(int) > opValue.Interface().(int) {
				return true, nil
			}
			return false, nil

		// Integer lower than ?
		case MatchingOpLowerThan:
			if _, ok := opValue.Interface().(int); !ok {
				return false, fmt.Errorf("integer is expected for lower-than operator")
			}

			// If realValue is a slice
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)

					// Check if the element is a int
					if _, ok := elemValue.Interface().(int); !ok {
						continue
					}

					// Check for match
					if elemValue.Interface().(int) < opValue.Interface().(int) {
						return true, nil
					}
				}
				return false, nil
			}

			if realValue.Kind() != reflect.Int {
				return false, nil
			}
			if realValue.Interface().(int) < opValue.Interface().(int) {
				return true, nil
			}
			return false, nil

		// Ignore these operators
		case MatchingOpSource, MatchingOpSourceKind:
			continue

		// List of pattern
		case MatchingKindRegexp:
			patternList := opValue.Interface().([]*regexp.Regexp)

			// If realValue is a slice
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)

					// Check if the element is a string
					if _, ok := elemValue.Interface().(string); !ok {
						continue
					}

					// Check for a match with the regex pattern
					for _, pattern := range patternList {
						if pattern.MatchString(elemValue.Interface().(string)) {
							return true, nil
						}
					}
				}
				// No match found in the slice
				return false, nil
			}

			if realValue.Kind() != reflect.String {
				return false, nil
			}
			for _, pattern := range patternList {
				if pattern.MatchString(realValue.Interface().(string)) {
					return true, nil
				}
			}
			// No match found in pattern list
			return false, nil

		// List of string
		case MatchingKindString:
			stringList := opValue.Interface().([]string)

			// If realValue is a slice
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)

					// Check if the element is a string
					if _, ok := elemValue.Interface().(string); !ok {
						continue
					}

					// Check for a match with the text
					for _, textItem := range stringList {
						if textItem == realValue.Interface().(string) {
							return true, nil
						}
					}
				}
				// No match found in the slice
				return false, nil
			}

			if realValue.Kind() != reflect.String {
				return false, nil
			}
			for _, textItem := range stringList {
				if textItem == realValue.Interface().(string) {
					return true, nil
				}
			}

			// No match found in string list
			return false, nil

		default:
			return false, fmt.Errorf("invalid operator '%s', ignore it", opKey.Interface().(string))
		}
	}
	return true, nil
}

// list can be provided by user in the config
// dns.qname:
//   - ".*\\.github\\.com$"
//   - "^www\\.google\\.com$"
func matchUserSlice(realValue, expectedValue reflect.Value) (bool, error) {
	match := false
	for i := 0; i < expectedValue.Len() && !match; i++ {
		reflectedSub := reflect.ValueOf(expectedValue.Index(i).Interface())

		switch reflectedSub.Kind() {
		case reflect.Int:
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len(); i++ {
					elemValue := realValue.Index(i)
					if _, ok := elemValue.Interface().(int); !ok {
						continue
					}
					if reflectedSub.Interface().(int) == elemValue.Interface().(int) {
						return true, nil
					}
				}
			}

			if realValue.Kind() != reflect.Int || realValue.Interface().(int) != reflectedSub.Interface().(int) {
				continue
			}
			match = true
		case reflect.String:
			pattern := regexp.MustCompile(reflectedSub.Interface().(string))
			if realValue.Kind() == reflect.Slice {
				for i := 0; i < realValue.Len() && !match; i++ {
					elemValue := realValue.Index(i)
					if _, ok := elemValue.Interface().(string); !ok {
						continue
					}
					// Check for a match with the regex pattern
					if pattern.MatchString(elemValue.Interface().(string)) {
						match = true
					}
				}
			}

			if realValue.Kind() != reflect.String {
				continue
			}

			if pattern.MatchString(realValue.Interface().(string)) {
				match = true
			}
		}
	}
	return match, nil
}

// boolean can be provided by user in the config
// dns.flags.qr: true
func matchUserBoolean(realValue, expectedValue reflect.Value) (bool, error) {
	// If realValue is a slice
	if realValue.Kind() == reflect.Slice {
		for i := 0; i < realValue.Len(); i++ {
			elemValue := realValue.Index(i)

			// Check if the element is a int
			if _, ok := elemValue.Interface().(bool); !ok {
				continue
			}

			// Check for match
			if expectedValue.Interface().(bool) == elemValue.Interface().(bool) {
				return true, nil
			}
		}
	}

	if realValue.Kind() != reflect.Bool {
		return false, nil
	}

	if expectedValue.Interface().(bool) != realValue.Interface().(bool) {
		return false, nil
	}
	return true, nil
}

// integer can be provided by user in the config
// dns.opcode: 0
func matchUserInteger(realValue, expectedValue reflect.Value) (bool, error) {
	// If realValue is a slice
	if realValue.Kind() == reflect.Slice {
		for i := 0; i < realValue.Len(); i++ {
			elemValue := realValue.Index(i)

			// Check if the element is a int
			if _, ok := elemValue.Interface().(int); !ok {
				continue
			}

			// Check for match
			if expectedValue.Interface().(int) == elemValue.Interface().(int) {
				return true, nil
			}
		}
	}

	if realValue.Kind() != reflect.Int {
		return false, nil
	}
	if expectedValue.Interface().(int) != realValue.Interface().(int) {
		return false, nil
	}

	return true, nil
}

// regexp can be provided by user in the config
// dns.qname: "^.*\\.github\\.com$"
func matchUserPattern(realValue, expectedValue reflect.Value) (bool, error) {
	pattern := regexp.MustCompile(expectedValue.Interface().(string))

	// If realValue is a slice
	if realValue.Kind() == reflect.Slice {
		for i := 0; i < realValue.Len(); i++ {
			elemValue := realValue.Index(i)

			// Check if the element is a string
			if _, ok := elemValue.Interface().(string); !ok {
				continue
			}

			// Check for a match with the regex pattern
			if pattern.MatchString(elemValue.Interface().(string)) {
				return true, nil
			}
		}
		// No match found in the slice
		return false, nil
	}

	// If realValue is not a string
	if realValue.Kind() != reflect.String {
		return false, nil
	}

	// Check for a match with the regex pattern
	if !pattern.MatchString(realValue.String()) {
		return false, nil
	}

	// Match found for a single value
	return true, nil
}

func getFieldByJSONTag(value reflect.Value, nestedKeys string) (reflect.Value, bool) {
	listKeys := strings.SplitN(nestedKeys, ".", 2)

	for j, jsonKey := range listKeys {
		// Iterate over the fields of the structure
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)

			// Get JSON tag
			tag := field.Tag.Get("json")
			tagClean := strings.TrimSuffix(tag, ",omitempty")

			// Check if the JSON tag matches
			if tagClean == jsonKey {
				// ptr
				switch field.Type.Kind() {
				// integer
				case reflect.Ptr:
					if fieldValue, found := getFieldByJSONTag(value.Field(i).Elem(), listKeys[j+1]); found {
						return fieldValue, true
					}

				// struct
				case reflect.Struct:
					if fieldValue, found := getFieldByJSONTag(value.Field(i), listKeys[j+1]); found {
						return fieldValue, true
					}

				// slice if a list
				case reflect.Slice:
					if fieldValue, leftKey, found := getSliceElement(value.Field(i), listKeys[j+1]); found {
						switch field.Type.Kind() {
						case reflect.Struct:
							if fieldValue, found := getFieldByJSONTag(fieldValue, leftKey); found {
								return fieldValue, true
							}
						case reflect.Slice:
							var result []interface{}
							for i := 0; i < fieldValue.Len(); i++ {

								if fieldValue.Index(i).Kind() == reflect.String || fieldValue.Index(i).Kind() == reflect.Int {
									result = append(result, fieldValue.Index(i).Interface())
								} else {
									if sliceValue, found := getFieldByJSONTag(fieldValue.Index(i), leftKey); found {
										result = append(result, sliceValue.Interface())
									}
								}
							}
							// If the list is not empty, return the list
							if len(result) > 0 {
								return reflect.ValueOf(result), true
							}
						default:
							return value.Field(i), true
						}
					}

				// int, string
				default:
					return value.Field(i), true
				}
			}
		}
	}

	return reflect.Value{}, false
}

func getSliceElement(sliceValue reflect.Value, nestedKeys string) (reflect.Value, string, bool) {
	listKeys := strings.SplitN(nestedKeys, ".", 2)
	leftKeys := ""
	if len(listKeys) > 1 {
		leftKeys = listKeys[1]
	}
	sliceIndex := listKeys[0]

	if sliceIndex == "*" {
		return sliceValue, leftKeys, true
	}

	// Convert the slice index from string to int
	index, err := strconv.Atoi(sliceIndex)
	if err != nil {
		// Handle the error (e.g., invalid index format)
		return reflect.Value{}, leftKeys, false
	}

	for i := 0; i < sliceValue.Len(); i++ {
		if index == i {
			return sliceValue.Index(i), leftKeys, true
		}
	}
	// If no match is found, return an empty reflect.Value
	return reflect.Value{}, leftKeys, false
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

func GetFlatDNSMessage() (ret map[string]interface{}, err error) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()
	ret, err = dm.Flatten()
	return
}

func GetReferenceDNSMessage() DNSMessage {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()
	return dm
}

func convertToString(value interface{}) string {
	switch v := value.(type) {
	case int:
		return strconv.Itoa(v)
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
