package dnsutils

import (
	"regexp"
)

var (
	DNSQuery      = "QUERY"
	DNSQueryQuiet = "Q"
	DNSReply      = "REPLY"
	DNSReplyQuiet = "R"
)

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

	QdCount int `json:"qdcount"`
	AnCount int `json:"ancount"`
	NsCount int `json:"nscount"`
	ArCount int `json:"arcount"`

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
	Latency          float64 `json:"latency"`
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

type CollectorPowerDNS struct {
	Tags                  []string          `json:"tags"`
	OriginalRequestSubnet string            `json:"original-request-subnet"`
	AppliedPolicy         string            `json:"applied-policy"`
	AppliedPolicyHit      string            `json:"applied-policy-hit"`
	AppliedPolicyKind     string            `json:"applied-policy-kind"`
	AppliedPolicyTrigger  string            `json:"applied-policy-trigger"`
	AppliedPolicyType     string            `json:"applied-policy-type"`
	Metadata              map[string]string `json:"metadata"`
	HTTPVersion           string            `json:"http-version"`
	MessageID             string            `json:"message-id"`
	InitialRequestorID    string            `json:"initial-requestor-id"`
	RequestorID           string            `json:"requestor-id"`
	DeviceName            string            `json:"device-name"`
	DeviceID              string            `json:"device-id"`
}

type LoggerOpenTelemetry struct {
	TraceID string `json:"trace-id"`
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
	PowerDNS        *CollectorPowerDNS     `json:"powerdns,omitempty"`
	OpenTelemetry   *LoggerOpenTelemetry   `json:"opentelemetry,omitempty"`
	Geo             *TransformDNSGeo       `json:"geoip,omitempty"`
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
		Type:            "-",
		MalformedPacket: false,
		Rcode:           "-",
		Qtype:           "-",
		Qname:           "-",
		Qclass:          "-",
		DNSRRs:          DNSRRs{Answers: []DNSAnswer{}, Nameservers: []DNSAnswer{}, Records: []DNSAnswer{}},
	}

	dm.EDNS = DNSExtended{
		Options: []DNSOption{},
	}
}

func (dm *DNSMessage) InitTransforms() {
	// init transforms
	dm.ATags = &TransformATags{}
	dm.Filtering = &TransformFiltering{}
	dm.MachineLearning = &TransformML{}
	dm.Reducer = &TransformReducer{}
	dm.Extracted = &TransformExtracted{}
	dm.PublicSuffix = &TransformPublicSuffix{}
	dm.Suspicious = &TransformSuspicious{}
	dm.Geo = &TransformDNSGeo{}
	dm.Relabeling = &TransformRelabeling{}
	// init collectors & loggers
	dm.PowerDNS = &CollectorPowerDNS{}
	dm.OpenTelemetry = &LoggerOpenTelemetry{}
}
