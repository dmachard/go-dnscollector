package pkgconfig

import (
	"reflect"

	"github.com/creasty/defaults"
)

type RelabelingConfig struct {
	Regex       string `yaml:"regex"`
	Replacement string `yaml:"replacement"`
}

type ConfigTransformers struct {
	UserPrivacy struct {
		Enable            bool   `yaml:"enable" default:"false"`
		AnonymizeIP       bool   `yaml:"anonymize-ip" default:"false"`
		AnonymizeIPV4Bits string `yaml:"anonymize-v4bits" default:"0.0.0.0/16"`
		AnonymizeIPV6Bits string `yaml:"anonymize-v6bits" default:"::/64"`
		MinimazeQname     bool   `yaml:"minimaze-qname" default:"false"`
		HashQueryIP       bool   `yaml:"hash-query-ip" default:"false"`
		HashReplyIP       bool   `yaml:"hash-reply-ip" default:"false"`
		HashIPAlgo        string `yaml:"hash-ip-algo" default:"sha1"`
	} `yaml:"user-privacy"`
	Normalize struct {
		Enable              bool `yaml:"enable" default:"false"`
		QnameLowerCase      bool `yaml:"qname-lowercase" default:"false"`
		RRLowerCase         bool `yaml:"rr-lowercase" default:"false"`
		QuietText           bool `yaml:"quiet-text" default:"false"`
		AddTld              bool `yaml:"add-tld" default:"false"`
		AddTldPlusOne       bool `yaml:"add-tld-plus-one" default:"false"`
		ReplaceNonPrintable bool `yaml:"qname-replace-nonprintable" default:"false"`
	} `yaml:"normalize"`
	Latency struct {
		Enable            bool `yaml:"enable" default:"false"`
		MeasureLatency    bool `yaml:"measure-latency" default:"false"`
		UnansweredQueries bool `yaml:"unanswered-queries" default:"false"`
		QueriesTimeout    int  `yaml:"queries-timeout" default:"2"`
	} `yaml:"latency"`
	Reducer struct {
		Enable                    bool     `yaml:"enable" default:"false"`
		RepetitiveTrafficDetector bool     `yaml:"repetitive-traffic-detector" default:"false"`
		QnamePlusOne              bool     `yaml:"qname-plus-one" default:"false"`
		WatchInterval             int      `yaml:"watch-interval" default:"5"`
		UniqueFields              []string `yaml:"unique-fields" default:"[\"dnstap.identity\", \"dnstap.operation\", \"network.query-ip\", \"dns.qname\", \"dns.qtype\"]"`
	} `yaml:"reducer"`
	Filtering struct {
		Enable          bool     `yaml:"enable" default:"false"`
		DropFqdnFile    string   `yaml:"drop-fqdn-file" default:""`
		DropDomainFile  string   `yaml:"drop-domain-file" default:""`
		KeepFqdnFile    string   `yaml:"keep-fqdn-file" default:""`
		KeepDomainFile  string   `yaml:"keep-domain-file" default:""`
		DropQueryIPFile string   `yaml:"drop-queryip-file" default:""`
		KeepQueryIPFile string   `yaml:"keep-queryip-file" default:""`
		KeepRdataFile   string   `yaml:"keep-rdata-file" default:""`
		DropRcodes      []string `yaml:"drop-rcodes,flow" default:"[]"`
		LogQueries      bool     `yaml:"log-queries" default:"true"`
		LogReplies      bool     `yaml:"log-replies" default:"true"`
		Downsample      int      `yaml:"downsample" default:"0"`
	} `yaml:"filtering"`
	GeoIP struct {
		Enable        bool   `yaml:"enable" default:"false"`
		LookupECS     bool   `yaml:"lookup-ecs" default:"false"`
		DBCountryFile string `yaml:"mmdb-country-file" default:""`
		DBCityFile    string `yaml:"mmdb-city-file" default:""`
		DBASNFile     string `yaml:"mmdb-asn-file" default:""`
	} `yaml:"geoip"`
	Suspicious struct {
		Enable             bool     `yaml:"enable" default:"false"`
		ThresholdQnameLen  int      `yaml:"threshold-qname-len" default:"100"`
		ThresholdPacketLen int      `yaml:"threshold-packet-len" default:"1000"`
		ThresholdSlow      float64  `yaml:"threshold-slow" default:"1.0"`
		CommonQtypes       []string `yaml:"common-qtypes,flow" default:"[\"A\", \"AAAA\", \"TXT\", \"CNAME\", \"PTR\", \"NAPTR\", \"DNSKEY\", \"SRV\", \"SOA\", \"NS\", \"MX\", \"DS\", \"HTTPS\"]"`
		UnallowedChars     []string `yaml:"unallowed-chars,flow" default:"[\"\\\"\", \"==\", \"/\", \":\"]"`
		ThresholdMaxLabels int      `yaml:"threshold-max-labels" default:"10"`
		WhitelistDomains   []string `yaml:"whitelist-domains,flow" default:"[\"\\\\.ip6\\\\.arpa\"]"`
	} `yaml:"suspicious"`
	Extract struct {
		Enable     bool `yaml:"enable" default:"false"`
		AddPayload bool `yaml:"add-payload" default:"false"`
	} `yaml:"extract"`
	MachineLearning struct {
		Enable      bool `yaml:"enable" default:"false"`
		AddFeatures bool `yaml:"add-features" default:"false"`
	} `yaml:"machine-learning"`
	ATags struct {
		Enable  bool     `yaml:"enable" default:"false"`
		AddTags []string `yaml:"add-tags,flow" default:"[]"`
	} `yaml:"atags"`
	Relabeling struct {
		Enable bool               `yaml:"enable" default:"false"`
		Rename []RelabelingConfig `yaml:"rename,flow"`
		Remove []RelabelingConfig `yaml:"remove,flow"`
	} `yaml:"relabeling"`
	Rewrite struct {
		Enable      bool                   `yaml:"enable" default:"false"`
		Identifiers map[string]interface{} `yaml:"identifiers,flow"`
	} `yaml:"rewrite"`
	NewDomainTracker struct {
		Enable           bool   `yaml:"enable" default:"false"`
		TTL              int    `yaml:"ttl" default:"3600"`
		CacheSize        int    `yaml:"cache-size" default:"100000"`
		WhiteDomainsFile string `yaml:"white-domains-file" default:""`
		PersistenceFile  string `yaml:"persistence-file" default:""`
	} `yaml:"new-domain-tracker"`
}

func (c *ConfigTransformers) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigTransformers) IsValid(userCfg map[string]interface{}) error {
	return CheckConfigWithTags(reflect.ValueOf(*c), userCfg)
}

func GetFakeConfigTransformers() *ConfigTransformers {
	config := &ConfigTransformers{}
	config.SetDefault()
	return config
}
