package dnsutils

import (
	"os"

	"gopkg.in/yaml.v3"
)

func IsValidMode(mode string) bool {
	switch mode {
	case
		MODE_TEXT,
		MODE_JSON:
		return true
	}
	return false
}

func IsValidTLS(mode string) bool {
	switch mode {
	case
		TLS_v10,
		TLS_v11,
		TLS_v12,
		TLS_v13:
		return true
	}
	return false
}

type MultiplexInOut struct {
	Name       string                 `yaml:"name"`
	Transforms map[string]interface{} `yaml:"transforms"`
	Params     map[string]interface{} `yaml:",inline"`
}

type MultiplexRoutes struct {
	Src []string `yaml:"from,flow"`
	Dst []string `yaml:"to,flow"`
}

type ConfigTransformers struct {
	PublicSuffix struct {
		Enable        bool `yaml:"enable"`
		AddTld        bool `yaml:"add-tld"`
		AddTldPlusOne bool `yaml:"add-tld-plus-one"`
	} `yaml:"public-suffix"`
	UserPrivacy struct {
		Enable        bool `yaml:"enable"`
		AnonymizeIP   bool `yaml:"anonymize-ip"`
		MinimazeQname bool `yaml:"minimaze-qname"`
	} `yaml:"user-privacy"`
	Normalize struct {
		Enable         bool `yaml:"enable"`
		QnameLowerCase bool `yaml:"qname-lowercase"`
	} `yaml:"normalize"`
	Filtering struct {
		Enable          bool     `yaml:"enable"`
		DropFqdnFile    string   `yaml:"drop-fqdn-file"`
		DropDomainFile  string   `yaml:"drop-domain-file"`
		KeepFqdnFile    string   `yaml:"keep-fqdn-file"`
		KeepDomainFile  string   `yaml:"keep-domain-file"`
		DropQueryIpFile string   `yaml:"drop-queryip-file"`
		KeepQueryIpFile string   `yaml:"keep-queryip-file"`
		DropRcodes      []string `yaml:"drop-rcodes,flow"`
		LogQueries      bool     `yaml:"log-queries"`
		LogReplies      bool     `yaml:"log-replies"`
		Downsample      int      `yaml:"downsample"`
	} `yaml:"filtering"`
	GeoIP struct {
		Enable        bool   `yaml:"enable"`
		DbCountryFile string `yaml:"mmdb-country-file"`
		DbCityFile    string `yaml:"mmdb-city-file"`
		DbAsnFile     string `yaml:"mmdb-asn-file"`
	} `yaml:"geoip"`
	Suspicious struct {
		Enable             bool     `yaml:"enable"`
		ThresholdQnameLen  int      `yaml:"threshold-qname-len"`
		ThresholdPacketLen int      `yaml:"threshold-packet-len"`
		ThresholdSlow      float64  `yaml:"threshold-slow"`
		CommonQtypes       []string `yaml:"common-qtypes,flow"`
		UnallowedChars     []string `yaml:"unallowed-chars,flow"`
		ThresholdMaxLabels int      `yaml:"threshold-max-labels"`
	} `yaml:"suspicious"`
}

func (c *ConfigTransformers) SetDefault() {
	c.PublicSuffix.Enable = false
	c.PublicSuffix.AddTld = false
	c.PublicSuffix.AddTldPlusOne = false

	c.Suspicious.Enable = false
	c.Suspicious.ThresholdQnameLen = 100
	c.Suspicious.ThresholdPacketLen = 1000
	c.Suspicious.ThresholdSlow = 1.0
	c.Suspicious.CommonQtypes = []string{"A", "AAAA", "TXT", "CNAME", "PTR",
		"NAPTR", "DNSKEY", "SRV", "SOA", "NS", "MX", "DS", "HTTPS"}
	c.Suspicious.UnallowedChars = []string{"\"", "==", "/", ":"}
	c.Suspicious.ThresholdMaxLabels = 10

	c.UserPrivacy.Enable = false
	c.UserPrivacy.AnonymizeIP = false
	c.UserPrivacy.MinimazeQname = false

	c.Normalize.Enable = false
	c.Normalize.QnameLowerCase = false

	c.Filtering.Enable = false
	c.Filtering.DropFqdnFile = ""
	c.Filtering.DropDomainFile = ""
	c.Filtering.KeepFqdnFile = ""
	c.Filtering.KeepDomainFile = ""
	c.Filtering.DropQueryIpFile = ""
	c.Filtering.DropRcodes = []string{}
	c.Filtering.LogQueries = true
	c.Filtering.LogReplies = true
	c.Filtering.Downsample = 0

	c.GeoIP.Enable = false
	c.GeoIP.DbCountryFile = ""
	c.GeoIP.DbCityFile = ""
	c.GeoIP.DbAsnFile = ""
}

/* main configuration */
type Config struct {
	Global struct {
		TextFormat string `yaml:"text-format"`
		Trace      struct {
			Verbose      bool   `yaml:"verbose"`
			LogMalformed bool   `yaml:"log-malformed"`
			Filename     string `yaml:"filename"`
			MaxSize      int    `yaml:"max-size"`
			MaxBackups   int    `yaml:"max-backups"`
		} `yaml:"trace"`
		ServerIdentity string `yaml:"server-identity"`
	} `yaml:"global"`

	Collectors struct {
		Tail struct {
			Enable       bool   `yaml:"enable"`
			TimeLayout   string `yaml:"time-layout"`
			PatternQuery string `yaml:"pattern-query"`
			PatternReply string `yaml:"pattern-reply"`
			FilePath     string `yaml:"file-path"`
		} `yaml:"tail"`
		Dnstap struct {
			Enable        bool   `yaml:"enable"`
			ListenIP      string `yaml:"listen-ip"`
			ListenPort    int    `yaml:"listen-port"`
			SockPath      string `yaml:"sock-path"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsMinVersion string `yaml:"tls-min-version"`
			CertFile      string `yaml:"cert-file"`
			KeyFile       string `yaml:"key-file"`
			CacheSupport  bool   `yaml:"cache-support"`
			QueryTimeout  int    `yaml:"query-timeout"`
			QuietText     bool   `yaml:"quiet-text"`
		} `yaml:"dnstap"`
		DnstapRelay struct {
			Enable        bool   `yaml:"enable"`
			ListenIP      string `yaml:"listen-ip"`
			ListenPort    int    `yaml:"listen-port"`
			SockPath      string `yaml:"sock-path"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsMinVersion string `yaml:"tls-min-version"`
			CertFile      string `yaml:"cert-file"`
			KeyFile       string `yaml:"key-file"`
		} `yaml:"dnstap-relay"`
		LiveCapture struct {
			Enable       bool   `yaml:"enable"`
			Port         int    `yaml:"port"`
			Device       string `yaml:"device"`
			DropQueries  bool   `yaml:"drop-queries"`
			DropReplies  bool   `yaml:"drop-replies"`
			CacheSupport bool   `yaml:"cache-support"`
			QueryTimeout int    `yaml:"query-timeout"`
		} `yaml:"sniffer"`
		PowerDNS struct {
			Enable        bool   `yaml:"enable"`
			ListenIP      string `yaml:"listen-ip"`
			ListenPort    int    `yaml:"listen-port"`
			QuietText     bool   `yaml:"quiet-text"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsMinVersion string `yaml:"tls-min-version"`
			CertFile      string `yaml:"cert-file"`
			KeyFile       string `yaml:"key-file"`
		} `yaml:"powerdns"`
		IngestPcap struct {
			Enable      bool   `yaml:"enable"`
			WatchDir    string `yaml:"watch-dir"`
			DnsPort     int    `yaml:"dns-port"`
			DropQueries bool   `yaml:"drop-queries"`
			DropReplies bool   `yaml:"drop-replies"`
			DeleteAfter bool   `yaml:"delete-after"`
		} `yaml:"pcap"`
	} `yaml:"collectors"`

	IngoingTransformers ConfigTransformers `yaml:"ingoing-transformers"`

	Loggers struct {
		Stdout struct {
			Enable     bool   `yaml:"enable"`
			Mode       string `yaml:"mode"`
			TextFormat string `yaml:"text-format"`
		} `yaml:"stdout"`
		Prometheus struct {
			Enable        bool   `yaml:"enable"`
			ListenIP      string `yaml:"listen-ip"`
			ListenPort    int    `yaml:"listen-port"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsMutual     bool   `yaml:"tls-mutual"`
			TlsMinVersion string `yaml:"tls-min-version"`
			CertFile      string `yaml:"cert-file"`
			KeyFile       string `yaml:"key-file"`
			PromPrefix    string `yaml:"prometheus-prefix"`
			TopN          int    `yaml:"top-n"`
		} `yaml:"prometheus"`
		RestAPI struct {
			Enable         bool   `yaml:"enable"`
			ListenIP       string `yaml:"listen-ip"`
			ListenPort     int    `yaml:"listen-port"`
			BasicAuthLogin string `yaml:"basic-auth-login"`
			BasicAuthPwd   string `yaml:"basic-auth-pwd"`
			TlsSupport     bool   `yaml:"tls-support"`
			TlsMinVersion  string `yaml:"tls-min-version"`
			CertFile       string `yaml:"cert-file"`
			KeyFile        string `yaml:"key-file"`
			TopN           int    `yaml:"top-n"`
		} `yaml:"restapi"`
		LogFile struct {
			Enable              bool   `yaml:"enable"`
			FilePath            string `yaml:"file-path"`
			MaxSize             int    `yaml:"max-size"`
			MaxFiles            int    `yaml:"max-files"`
			FlushInterval       int    `yaml:"flush-interval"`
			Compress            bool   `yaml:"compress"`
			CompressInterval    int    `yaml:"compress-interval"`
			CompressPostCommand string `yaml:"compress-postcommand"`
			Mode                string `yaml:"mode"`
			PostRotateCommand   string `yaml:"postrotate-command"`
			PostRotateDelete    bool   `yaml:"postrotate-delete-success"`
			TextFormat          string `yaml:"text-format"`
		} `yaml:"logfile"`
		Dnstap struct {
			Enable        bool   `yaml:"enable"`
			RemoteAddress string `yaml:"remote-address"`
			RemotePort    int    `yaml:"remote-port"`
			SockPath      string `yaml:"sock-path"`
			RetryInterval int    `yaml:"retry-interval"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
			ServerId      string `yaml:"server-id"`
		} `yaml:"dnstap"`
		TcpClient struct {
			Enable        bool   `yaml:"enable"`
			RemoteAddress string `yaml:"remote-address"`
			RemotePort    int    `yaml:"remote-port"`
			SockPath      string `yaml:"sock-path"`
			RetryInterval int    `yaml:"retry-interval"`
			Transport     string `yaml:"transport"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
			Mode          string `yaml:"mode"`
			TextFormat    string `yaml:"text-format"`
			Delimiter     string `yaml:"delimiter"`
		} `yaml:"tcpclient"`
		Syslog struct {
			Enable        bool   `yaml:"enable"`
			Severity      string `yaml:"severity"`
			Facility      string `yaml:"facility"`
			Transport     string `yaml:"transport"`
			RemoteAddress string `yaml:"remote-address"`
			TextFormat    string `yaml:"text-format"`
			Mode          string `yaml:"mode"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
			Format        string `yaml:"format"`
		} `yaml:"syslog"`
		Fluentd struct {
			Enable        bool   `yaml:"enable"`
			RemoteAddress string `yaml:"remote-address"`
			RemotePort    int    `yaml:"remote-port"`
			SockPath      string `yaml:"sock-path"`
			RetryInterval int    `yaml:"retry-interval"`
			Transport     string `yaml:"transport"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
			Tag           string `yaml:"tag"`
		} `yaml:"fluentd"`
		InfluxDB struct {
			Enable        bool   `yaml:"enable"`
			ServerURL     string `yaml:"server-url"`
			AuthToken     string `yaml:"auth-token"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
			Bucket        string `yaml:"bucket"`
			Organization  string `yaml:"organization"`
		} `yaml:"influxdb"`
		LokiClient struct {
			Enable         bool   `yaml:"enable"`
			ServerURL      string `yaml:"server-url"`
			JobName        string `yaml:"job-name"`
			Mode           string `yaml:"mode"`
			FlushInterval  int    `yaml:"flush-interval"`
			BatchSize      int    `yaml:"batch-size"`
			RetryInterval  int    `yaml:"retry-interval"`
			TextFormat     string `yaml:"text-format"`
			ProxyURL       string `yaml:"proxy-url"`
			TlsInsecure    bool   `yaml:"tls-insecure"`
			TlsMinVersion  string `yaml:"tls-min-version"`
			BasicAuthLogin string `yaml:"basic-auth-login"`
			BasicAuthPwd   string `yaml:"basic-auth-pwd"`
			TenantId       string `yaml:"tenant-id"`
		} `yaml:"lokiclient"`
		Statsd struct {
			Enable        bool   `yaml:"enable"`
			Prefix        string `yaml:"prefix"`
			RemoteAddress string `yaml:"remote-address"`
			RemotePort    int    `yaml:"remote-port"`
			Transport     string `yaml:"transport"`
			FlushInterval int    `yaml:"flush-interval"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
		} `yaml:"statsd"`
		ElasticSearchClient struct {
			Enable bool   `yaml:"enable"`
			URL    string `yaml:"url"`
		} `yaml:"elasticsearch"`
	} `yaml:"loggers"`

	OutgoingTransformers ConfigTransformers `yaml:"outgoing-transformers"`

	Multiplexer struct {
		Collectors []MultiplexInOut  `yaml:"collectors"`
		Loggers    []MultiplexInOut  `yaml:"loggers"`
		Routes     []MultiplexRoutes `yaml:"routes"`
	} `yaml:"multiplexer"`
}

func (c *Config) SetDefault() {
	// global config
	c.Global.TextFormat = "timestamp identity operation rcode queryip queryport family protocol length qname qtype latency"

	c.Global.Trace.Verbose = false
	c.Global.Trace.LogMalformed = false
	c.Global.Trace.Filename = ""
	c.Global.Trace.MaxSize = 10
	c.Global.Trace.MaxBackups = 10
	c.Global.ServerIdentity = ""

	// multiplexer
	c.Multiplexer.Collectors = []MultiplexInOut{}
	c.Multiplexer.Loggers = []MultiplexInOut{}
	c.Multiplexer.Routes = []MultiplexRoutes{}

	// Collectors
	c.Collectors.Tail.Enable = false
	c.Collectors.Tail.TimeLayout = ""
	c.Collectors.Tail.PatternQuery = ""
	c.Collectors.Tail.PatternReply = ""
	c.Collectors.Tail.FilePath = ""

	c.Collectors.Dnstap.Enable = false
	c.Collectors.Dnstap.ListenIP = ANY_IP
	c.Collectors.Dnstap.ListenPort = 6000
	c.Collectors.Dnstap.SockPath = ""
	c.Collectors.Dnstap.TlsSupport = false
	c.Collectors.Dnstap.TlsMinVersion = TLS_v12
	c.Collectors.Dnstap.CertFile = ""
	c.Collectors.Dnstap.KeyFile = ""
	c.Collectors.Dnstap.QueryTimeout = 5
	c.Collectors.Dnstap.CacheSupport = false
	c.Collectors.Dnstap.QuietText = false

	c.Collectors.DnstapRelay.Enable = false
	c.Collectors.DnstapRelay.ListenIP = ANY_IP
	c.Collectors.DnstapRelay.ListenPort = 6000
	c.Collectors.DnstapRelay.SockPath = ""
	c.Collectors.DnstapRelay.TlsSupport = false
	c.Collectors.DnstapRelay.TlsMinVersion = TLS_v12
	c.Collectors.DnstapRelay.CertFile = ""
	c.Collectors.DnstapRelay.KeyFile = ""

	c.Collectors.LiveCapture.Enable = false
	c.Collectors.LiveCapture.Port = 53
	c.Collectors.LiveCapture.Device = ""
	c.Collectors.LiveCapture.DropQueries = false
	c.Collectors.LiveCapture.DropReplies = false
	c.Collectors.LiveCapture.QueryTimeout = 5
	c.Collectors.LiveCapture.CacheSupport = true

	c.Collectors.PowerDNS.Enable = false
	c.Collectors.PowerDNS.ListenIP = ANY_IP
	c.Collectors.PowerDNS.ListenPort = 6001
	c.Collectors.PowerDNS.QuietText = false
	c.Collectors.PowerDNS.TlsSupport = false
	c.Collectors.PowerDNS.TlsMinVersion = TLS_v12
	c.Collectors.PowerDNS.CertFile = ""
	c.Collectors.PowerDNS.KeyFile = ""

	c.Collectors.IngestPcap.Enable = false
	c.Collectors.IngestPcap.WatchDir = ""
	c.Collectors.IngestPcap.DnsPort = 53
	c.Collectors.IngestPcap.DropQueries = false
	c.Collectors.IngestPcap.DropReplies = false
	c.Collectors.IngestPcap.DeleteAfter = false

	// Transformers for collectors
	c.IngoingTransformers.SetDefault()

	// Loggers
	c.Loggers.Stdout.Enable = false
	c.Loggers.Stdout.Mode = MODE_TEXT
	c.Loggers.Stdout.TextFormat = ""

	c.Loggers.Dnstap.Enable = false
	c.Loggers.Dnstap.RemoteAddress = LOCALHOST_IP
	c.Loggers.Dnstap.RemotePort = 6000
	c.Loggers.Dnstap.RetryInterval = 5
	c.Loggers.Dnstap.SockPath = ""
	c.Loggers.Dnstap.TlsSupport = false
	c.Loggers.Dnstap.TlsInsecure = false
	c.Loggers.Dnstap.TlsMinVersion = TLS_v12
	c.Loggers.Dnstap.ServerId = ""

	c.Loggers.LogFile.Enable = false
	c.Loggers.LogFile.FilePath = ""
	c.Loggers.LogFile.FlushInterval = 10
	c.Loggers.LogFile.MaxSize = 100
	c.Loggers.LogFile.MaxFiles = 10
	c.Loggers.LogFile.Compress = false
	c.Loggers.LogFile.CompressInterval = 60
	c.Loggers.LogFile.CompressPostCommand = ""
	c.Loggers.LogFile.Mode = MODE_TEXT
	c.Loggers.LogFile.PostRotateCommand = ""
	c.Loggers.LogFile.PostRotateDelete = false
	c.Loggers.LogFile.TextFormat = ""

	c.Loggers.Prometheus.Enable = false
	c.Loggers.Prometheus.ListenIP = LOCALHOST_IP
	c.Loggers.Prometheus.ListenPort = 8081
	c.Loggers.Prometheus.TlsSupport = false
	c.Loggers.Prometheus.TlsMutual = false
	c.Loggers.Prometheus.TlsMinVersion = TLS_v12
	c.Loggers.Prometheus.CertFile = ""
	c.Loggers.Prometheus.KeyFile = ""
	c.Loggers.Prometheus.PromPrefix = PROG_NAME
	c.Loggers.Prometheus.TopN = 10

	c.Loggers.RestAPI.Enable = false
	c.Loggers.RestAPI.ListenIP = LOCALHOST_IP
	c.Loggers.RestAPI.ListenPort = 8080
	c.Loggers.RestAPI.BasicAuthLogin = "admin"
	c.Loggers.RestAPI.BasicAuthPwd = "changeme"
	c.Loggers.RestAPI.TlsSupport = false
	c.Loggers.RestAPI.TlsMinVersion = TLS_v12
	c.Loggers.RestAPI.CertFile = ""
	c.Loggers.RestAPI.KeyFile = ""
	c.Loggers.RestAPI.TopN = 100

	c.Loggers.TcpClient.Enable = false
	c.Loggers.TcpClient.RemoteAddress = LOCALHOST_IP
	c.Loggers.TcpClient.RemotePort = 9999
	c.Loggers.TcpClient.SockPath = ""
	c.Loggers.TcpClient.RetryInterval = 5
	c.Loggers.TcpClient.Transport = "tcp"
	c.Loggers.TcpClient.TlsSupport = false
	c.Loggers.TcpClient.TlsInsecure = false
	c.Loggers.TcpClient.TlsMinVersion = TLS_v12
	c.Loggers.TcpClient.Mode = MODE_JSON
	c.Loggers.TcpClient.TextFormat = ""
	c.Loggers.TcpClient.Delimiter = "\n"

	c.Loggers.Syslog.Enable = false
	c.Loggers.Syslog.Severity = "INFO"
	c.Loggers.Syslog.Facility = "DAEMON"
	c.Loggers.Syslog.Transport = "local"
	c.Loggers.Syslog.RemoteAddress = "127.0.0.1:514"
	c.Loggers.Syslog.TextFormat = ""
	c.Loggers.Syslog.Mode = MODE_TEXT
	c.Loggers.Syslog.TlsSupport = false
	c.Loggers.Syslog.TlsInsecure = false
	c.Loggers.Syslog.TlsMinVersion = TLS_v12

	c.Loggers.Fluentd.Enable = false
	c.Loggers.Fluentd.RemoteAddress = LOCALHOST_IP
	c.Loggers.Fluentd.RemotePort = 24224
	c.Loggers.Fluentd.SockPath = ""
	c.Loggers.Fluentd.RetryInterval = 5
	c.Loggers.Fluentd.Transport = "tcp"
	c.Loggers.Fluentd.TlsSupport = false
	c.Loggers.Fluentd.TlsInsecure = false
	c.Loggers.Fluentd.TlsMinVersion = TLS_v12
	c.Loggers.Fluentd.Tag = "dns.collector"

	c.Loggers.InfluxDB.Enable = false
	c.Loggers.InfluxDB.ServerURL = "http://localhost:8086"
	c.Loggers.InfluxDB.AuthToken = ""
	c.Loggers.InfluxDB.TlsSupport = false
	c.Loggers.InfluxDB.TlsInsecure = false
	c.Loggers.InfluxDB.TlsMinVersion = TLS_v12
	c.Loggers.InfluxDB.Bucket = ""
	c.Loggers.InfluxDB.Organization = ""

	c.Loggers.LokiClient.Enable = false
	c.Loggers.LokiClient.ServerURL = "http://localhost:3100/loki/api/v1/push"
	c.Loggers.LokiClient.JobName = PROG_NAME
	c.Loggers.LokiClient.Mode = MODE_TEXT
	c.Loggers.LokiClient.FlushInterval = 5
	c.Loggers.LokiClient.BatchSize = 1024 * 1024
	c.Loggers.LokiClient.RetryInterval = 10
	c.Loggers.LokiClient.TextFormat = ""
	c.Loggers.LokiClient.ProxyURL = ""
	c.Loggers.LokiClient.TlsInsecure = false
	c.Loggers.LokiClient.TlsMinVersion = TLS_v12
	c.Loggers.LokiClient.BasicAuthLogin = ""
	c.Loggers.LokiClient.BasicAuthPwd = ""
	c.Loggers.LokiClient.TenantId = ""

	c.Loggers.Statsd.Enable = false
	c.Loggers.Statsd.Prefix = PROG_NAME
	c.Loggers.Statsd.RemoteAddress = LOCALHOST_IP
	c.Loggers.Statsd.RemotePort = 8125
	c.Loggers.Statsd.Transport = "udp"
	c.Loggers.Statsd.FlushInterval = 10
	c.Loggers.Statsd.TlsSupport = false
	c.Loggers.Statsd.TlsInsecure = false
	c.Loggers.Statsd.TlsMinVersion = TLS_v12

	c.Loggers.ElasticSearchClient.Enable = false
	c.Loggers.ElasticSearchClient.URL = ""

	// Transformers for loggers
	c.OutgoingTransformers.SetDefault()

}

func (c *Config) GetServerIdentity() string {
	if len(c.Global.ServerIdentity) > 0 {
		return c.Global.ServerIdentity
	} else {
		hostname, err := os.Hostname()
		if err == nil {
			return hostname
		} else {
			return "undefined"
		}
	}
}

func ReloadConfig(configPath string, config *Config) error {
	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return err
	}
	return nil
}

func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}
	config.SetDefault()

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func GetFakeConfig() *Config {
	config := &Config{}
	config.SetDefault()
	return config
}

func GetFakeConfigTransformers() *ConfigTransformers {
	config := &ConfigTransformers{}
	config.SetDefault()
	return config
}
