package pkgconfig

type ConfigTransformers struct {
	UserPrivacy struct {
		Enable        bool `yaml:"enable"`
		AnonymizeIP   bool `yaml:"anonymize-ip"`
		MinimazeQname bool `yaml:"minimaze-qname"`
		HashIP        bool `yaml:"hash-ip"`
	} `yaml:"user-privacy"`
	Normalize struct {
		Enable         bool `yaml:"enable"`
		QnameLowerCase bool `yaml:"qname-lowercase"`
		QuietText      bool `yaml:"quiet-text"`
		AddTld         bool `yaml:"add-tld"`
		AddTldPlusOne  bool `yaml:"add-tld-plus-one"`
	} `yaml:"normalize"`
	Latency struct {
		Enable            bool `yaml:"enable"`
		MeasureLatency    bool `yaml:"measure-latency"`
		UnansweredQueries bool `yaml:"unanswered-queries"`
		QueriesTimeout    int  `yaml:"queries-timeout"`
	} `yaml:"latency"`
	Reducer struct {
		Enable                    bool `yaml:"enable"`
		RepetitiveTrafficDetector bool `yaml:"repetitive-traffic-detector"`
		QnamePlusOne              bool `yaml:"qname-plus-one"`
		WatchInterval             int  `yaml:"watch-interval"`
	} `yaml:"reducer"`
	Filtering struct {
		Enable          bool     `yaml:"enable"`
		DropFqdnFile    string   `yaml:"drop-fqdn-file"`
		DropDomainFile  string   `yaml:"drop-domain-file"`
		KeepFqdnFile    string   `yaml:"keep-fqdn-file"`
		KeepDomainFile  string   `yaml:"keep-domain-file"`
		DropQueryIPFile string   `yaml:"drop-queryip-file"`
		KeepQueryIPFile string   `yaml:"keep-queryip-file"`
		KeepRdataFile   string   `yaml:"keep-rdata-file"`
		DropRcodes      []string `yaml:"drop-rcodes,flow"`
		LogQueries      bool     `yaml:"log-queries"`
		LogReplies      bool     `yaml:"log-replies"`
		Downsample      int      `yaml:"downsample"`
	} `yaml:"filtering"`
	GeoIP struct {
		Enable        bool   `yaml:"enable"`
		DBCountryFile string `yaml:"mmdb-country-file"`
		DBCityFile    string `yaml:"mmdb-city-file"`
		DBASNFile     string `yaml:"mmdb-asn-file"`
	} `yaml:"geoip"`
	Suspicious struct {
		Enable             bool     `yaml:"enable"`
		ThresholdQnameLen  int      `yaml:"threshold-qname-len"`
		ThresholdPacketLen int      `yaml:"threshold-packet-len"`
		ThresholdSlow      float64  `yaml:"threshold-slow"`
		CommonQtypes       []string `yaml:"common-qtypes,flow"`
		UnallowedChars     []string `yaml:"unallowed-chars,flow"`
		ThresholdMaxLabels int      `yaml:"threshold-max-labels"`
		WhitelistDomains   []string `yaml:"whitelist-domains,flow"`
	} `yaml:"suspicious"`
	Extract struct {
		Enable     bool `yaml:"enable"`
		AddPayload bool `yaml:"add-payload"`
	} `yaml:"extract"`
	MachineLearning struct {
		Enable      bool `yaml:"enable"`
		AddFeatures bool `yaml:"add-features"`
	} `yaml:"machine-learning"`
	ATags struct {
		Enable bool     `yaml:"enable"`
		Tags   []string `yaml:"tags,flow"`
	} `yaml:"atags"`
}

func (c *ConfigTransformers) SetDefault() {
	c.Suspicious.Enable = false
	c.Suspicious.ThresholdQnameLen = 100
	c.Suspicious.ThresholdPacketLen = 1000
	c.Suspicious.ThresholdSlow = 1.0
	c.Suspicious.CommonQtypes = []string{"A", "AAAA", "TXT", "CNAME", "PTR",
		"NAPTR", "DNSKEY", "SRV", "SOA", "NS", "MX", "DS", "HTTPS"}
	c.Suspicious.UnallowedChars = []string{"\"", "==", "/", ":"}
	c.Suspicious.ThresholdMaxLabels = 10
	c.Suspicious.WhitelistDomains = []string{"\\.ip6\\.arpa"}

	c.UserPrivacy.Enable = false
	c.UserPrivacy.AnonymizeIP = false
	c.UserPrivacy.MinimazeQname = false
	c.UserPrivacy.HashIP = false

	c.Normalize.Enable = false
	c.Normalize.QnameLowerCase = false
	c.Normalize.QuietText = false
	c.Normalize.AddTld = false
	c.Normalize.AddTldPlusOne = false

	c.Latency.Enable = false
	c.Latency.MeasureLatency = false
	c.Latency.UnansweredQueries = false
	c.Latency.QueriesTimeout = 2

	c.Reducer.Enable = false
	c.Reducer.RepetitiveTrafficDetector = false
	c.Reducer.QnamePlusOne = false
	c.Reducer.WatchInterval = 5

	c.Filtering.Enable = false
	c.Filtering.DropFqdnFile = ""
	c.Filtering.DropDomainFile = ""
	c.Filtering.KeepFqdnFile = ""
	c.Filtering.KeepDomainFile = ""
	c.Filtering.DropQueryIPFile = ""
	c.Filtering.DropRcodes = []string{}
	c.Filtering.LogQueries = true
	c.Filtering.LogReplies = true
	c.Filtering.Downsample = 0

	c.GeoIP.Enable = false
	c.GeoIP.DBCountryFile = ""
	c.GeoIP.DBCityFile = ""
	c.GeoIP.DBASNFile = ""

	c.Extract.Enable = false
	c.Extract.AddPayload = false

	c.MachineLearning.Enable = false
	c.MachineLearning.AddFeatures = false

	c.ATags.Enable = false
	c.ATags.Tags = []string{}
}

func GetFakeConfigTransformers() *ConfigTransformers {
	config := &ConfigTransformers{}
	config.SetDefault()
	return config
}
