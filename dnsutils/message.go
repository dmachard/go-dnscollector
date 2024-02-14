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
	"github.com/nqd/flat"
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
	RD bool `json:"rd" msgpack:"rd"`
	CD bool `json:"cd" msgpack:"cd"`
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
	ID      int    `json:"id" msgpack:"id"`
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
	PolicyRule       string  `json:"policy-rule" msgpack:"policy-rule"`
	PolicyType       string  `json:"policy-type" msgpack:"policy-type"`
	PolicyMatch      string  `json:"policy-match" msgpack:"policy-match"`
	PolicyAction     string  `json:"policy-action" msgpack:"policy-action"`
	PolicyValue      string  `json:"policy-value" msgpack:"policy-value"`
	PeerName         string  `json:"peer-name" msgpack:"peer-name"`
}

type PowerDNS struct {
	Tags                  []string          `json:"tags" msgpack:"tags"`
	OriginalRequestSubnet string            `json:"original-request-subnet" msgpack:"original-request-subnet"`
	AppliedPolicy         string            `json:"applied-policy" msgpack:"applied-policy"`
	AppliedPolicyHit      string            `json:"applied-policy-hit" msgpack:"applied-policy-hit"`
	AppliedPolicyKind     string            `json:"applied-policy-kind" msgpack:"applied-policy-kind"`
	AppliedPolicyTrigger  string            `json:"applied-policy-trigger" msgpack:"applied-policy-trigger"`
	AppliedPolicyType     string            `json:"applied-policy-type" msgpack:"applied-policy-type"`
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
	Occurrences      int `json:"occurrences" msgpack:"occurrences"`
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
	Occurrences           int     `json:"occurrences" msgpack:"occurrences"`
	UncommonQtypes        int     `json:"uncommon-qtypes" msgpack:"uncommon-qtypes"`
}

type TransformATags struct {
	Tags []string `json:"tags" msgpack:"tags"`
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
	ATags           *TransformATags        `json:"atags,omitempty" msgpack:"atags"`
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
	}

	dm.DNS = DNS{
		ID:              0,
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
}

func (dm *DNSMessage) handleGeoIPDirectives(directives []string, s *strings.Builder) error {
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
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handlePdnsDirectives(directives []string, s *strings.Builder) error {
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
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleSuspiciousDirectives(directives []string, s *strings.Builder) error {
	if dm.Suspicious == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "suspicious-score":
			s.WriteString(strconv.Itoa(int(dm.Suspicious.Score)))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handlePublicSuffixDirectives(directives []string, s *strings.Builder) error {
	if dm.PublicSuffix == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "publixsuffix-tld":
			s.WriteString(dm.PublicSuffix.QnamePublicSuffix)
		case directive == "publixsuffix-etld+1":
			s.WriteString(dm.PublicSuffix.QnameEffectiveTLDPlusOne)
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleExtractedDirectives(directives []string, s *strings.Builder) error {
	if dm.Extracted == nil {
		s.WriteString("-")
		return nil
	}
	switch directive := directives[0]; {
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

func (dm *DNSMessage) handleFilteringDirectives(directives []string, s *strings.Builder) error {
	if dm.Filtering == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
		case directive == "filtering-sample-rate":
			s.WriteString(strconv.Itoa(dm.Filtering.SampleRate))
		default:
			return errors.New(ErrorUnexpectedDirective + directive)
		}
	}
	return nil
}

func (dm *DNSMessage) handleReducerDirectives(directives []string, s *strings.Builder) error {
	if dm.Reducer == nil {
		s.WriteString("-")
	} else {
		switch directive := directives[0]; {
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

func (dm *DNSMessage) handleMachineLearningDirectives(directives []string, s *strings.Builder) error {
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
			err := dm.handlePdnsDirectives(directives, &s)
			if err != nil {
				return nil, err
			}

		// more directives from transformers
		case ReducerDirectives.MatchString(directive):
			err := dm.handleReducerDirectives(directives, &s)
			if err != nil {
				return nil, err
			}
		case GeoIPDirectives.MatchString(directive):
			err := dm.handleGeoIPDirectives(directives, &s)
			if err != nil {
				return nil, err
			}
		case SuspiciousDirectives.MatchString(directive):
			err := dm.handleSuspiciousDirectives(directives, &s)
			if err != nil {
				return nil, err
			}
		case PublicSuffixDirectives.MatchString(directive):
			err := dm.handlePublicSuffixDirectives(directives, &s)
			if err != nil {
				return nil, err
			}
		case ExtractedDirectives.MatchString(directive):
			err := dm.handleExtractedDirectives(directives, &s)
			if err != nil {
				return nil, err
			}
		case MachineLearningDirectives.MatchString(directive):
			err := dm.handleMachineLearningDirectives(directives, &s)
			if err != nil {
				return nil, err
			}
		case FilteringDirectives.MatchString(directive):
			err := dm.handleFilteringDirectives(directives, &s)
			if err != nil {
				return nil, err
			}

		// error unsupport directive for text format
		default:
			return nil, errors.New(ErrorUnexpectedDirective + word)
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
		} else if port < 0 || port > math.MaxUint32 {
			return nil, errors.New("invalid response port value")
		} else {
			rport = uint32(port)
		}
	}

	if dm.NetworkInfo.QueryPort != "-" {
		if port, err := strconv.Atoi(dm.NetworkInfo.QueryPort); err != nil {
			return nil, err
		} else if port < 0 || port > math.MaxUint32 {
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
