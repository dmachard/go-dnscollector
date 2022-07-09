package dnsutils

import (
	"os"

	"gopkg.in/yaml.v3"
)

func IsValidMode(mode string) bool {
	switch mode {
	case
		"text",
		"json":
		return true
	}
	return false
}

type MultiplexTransformers struct {
	Name   string
	Params map[string]interface{} `yaml:",inline"`
}

type MultiplexInOut struct {
	Name   string
	Params map[string]interface{} `yaml:",inline"`
}

type MultiplexRoutes struct {
	Src        []string `yaml:"from,flow"`
	Transforms []string `yaml:"transforms,flow"`
	Dst        []string `yaml:"to,flow"`
}

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
			Enable       bool   `yaml:"enable"`
			ListenIP     string `yaml:"listen-ip"`
			ListenPort   int    `yaml:"listen-port"`
			SockPath     string `yaml:"sock-path"`
			TlsSupport   bool   `yaml:"tls-support"`
			CertFile     string `yaml:"cert-file"`
			KeyFile      string `yaml:"key-file"`
			CacheSupport bool   `yaml:"cache-support"`
			QueryTimeout int    `yaml:"query-timeout"`
			QuietText    bool   `yaml:"quiet-text"`
		} `yaml:"dnstap"`
		DnsSniffer struct {
			Enable            bool   `yaml:"enable"`
			Port              int    `yaml:"port"`
			Device            string `yaml:"device"`
			CaptureDnsQueries bool   `yaml:"capture-dns-queries"`
			CaptureDnsReplies bool   `yaml:"capture-dns-replies"`
			CacheSupport      bool   `yaml:"cache-support"`
			QueryTimeout      int    `yaml:"query-timeout"`
		} `yaml:"dns-sniffer"`
		PowerDNS struct {
			Enable     bool   `yaml:"enable"`
			ListenIP   string `yaml:"listen-ip"`
			ListenPort int    `yaml:"listen-port"`
			QuietText  bool   `yaml:"quiet-text"`
			TlsSupport bool   `yaml:"tls-support"`
			CertFile   string `yaml:"cert-file"`
			KeyFile    string `yaml:"key-file"`
		} `yaml:"powerdns"`
	} `yaml:"collectors"`

	Transformers struct {
		UserPrivacy struct {
			AnonymizeIP   bool `yaml:"anonymize-ip"`
			MinimazeQname bool `yaml:"minimaze-qname"`
		} `yaml:"user-privacy"`
		Normalize struct {
			QnameLowerCase bool `yaml:"lowercase-qname"`
		} `yaml:"normalize"`
		Filtering struct {
			DropFqdnFile    string   `yaml:"drop-fqdn-file"`
			DropDomainFile  string   `yaml:"drop-domain-file"`
			DropQueryIpFile string   `yaml:"drop-queryip-file"`
			KeepQueryIpFile string   `yaml:"keep-queryip-file"`
			DropRcodes      []string `yaml:"drop-rcodes,flow"`
			LogQueries      bool     `yaml:"log-queries"`
			LogReplies      bool     `yaml:"log-replies"`
		} `yaml:"filtering"`
		GeoIP struct {
			DbCountryFile string `yaml:"mmdb-country-file"`
			DbCityFile    string `yaml:"mmdb-city-file"`
			DbAsnFile     string `yaml:"mmdb-asn-file"`
		} `yaml:"geoip"`
	} `yaml:"transformers"`

	Loggers struct {
		Stdout struct {
			Enable     bool   `yaml:"enable"`
			Mode       string `yaml:"mode"`
			TextFormat string `yaml:"text-format"`
		} `yaml:"stdout"`
		Prometheus struct {
			Enable         bool   `yaml:"enable"`
			ListenIP       string `yaml:"listen-ip"`
			ListenPort     int    `yaml:"listen-port"`
			BasicAuthLogin string `yaml:"basic-auth-login"`
			BasicAuthPwd   string `yaml:"basic-auth-pwd"`
			TlsSupport     bool   `yaml:"tls-support"`
			TlsMutual      bool   `yaml:"tls-mutual"`
			CertFile       string `yaml:"cert-file"`
			KeyFile        string `yaml:"key-file"`
			PromPrefix     string `yaml:"prometheus-prefix"`
			TopN           int    `yaml:"top-n"`
		} `yaml:"prometheus"`
		WebServer struct {
			Enable                  bool     `yaml:"enable"`
			ListenIP                string   `yaml:"listen-ip"`
			ListenPort              int      `yaml:"listen-port"`
			BasicAuthLogin          string   `yaml:"basic-auth-login"`
			BasicAuthPwd            string   `yaml:"basic-auth-pwd"`
			TlsSupport              bool     `yaml:"tls-support"`
			CertFile                string   `yaml:"cert-file"`
			KeyFile                 string   `yaml:"key-file"`
			PromPrefix              string   `yaml:"prometheus-prefix"`
			StatsTopMaxItems        int      `yaml:"top-max-items"`
			StatsThresholdQnameLen  int      `yaml:"threshold-qname-len"`
			StatsThresholdPacketLen int      `yaml:"threshold-packet-len"`
			StatsThresholdSlow      float64  `yaml:"threshold-slow"`
			StatsCommonQtypes       []string `yaml:"common-qtypes,flow"`
		} `yaml:"webserver"`
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
			Tag           string `yaml:"tag"`
		} `yaml:"fluentd"`
		PcapFile struct {
			Enable            bool   `yaml:"enable"`
			FilePath          string `yaml:"file-path"`
			MaxSize           int    `yaml:"max-size"`
			MaxFiles          int    `yaml:"max-files"`
			Compress          bool   `yaml:"compress"`
			CompressInterval  int    `yaml:"compress-interval"`
			PostRotateCommand string `yaml:"postrotate-command"`
			PostRotateDelete  bool   `yaml:"postrotate-delete-success"`
		} `yaml:"pcapfile"`
		InfluxDB struct {
			Enable       bool   `yaml:"enable"`
			ServerURL    string `yaml:"server-url"`
			AuthToken    string `yaml:"auth-token"`
			TlsSupport   bool   `yaml:"tls-support"`
			TlsInsecure  bool   `yaml:"tls-insecure"`
			Bucket       string `yaml:"bucket"`
			Organization string `yaml:"organization"`
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
		} `yaml:"statsd"`
	} `yaml:"loggers"`

	Multiplexer struct {
		Collectors   []MultiplexInOut        `yaml:"collectors"`
		Transformers []MultiplexTransformers `yaml:"transformers"`
		Loggers      []MultiplexInOut        `yaml:"loggers"`
		Routes       []MultiplexRoutes       `yaml:"routes"`
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
	c.Collectors.Dnstap.ListenIP = "0.0.0.0"
	c.Collectors.Dnstap.ListenPort = 6000
	c.Collectors.Dnstap.SockPath = ""
	c.Collectors.Dnstap.TlsSupport = false
	c.Collectors.Dnstap.CertFile = ""
	c.Collectors.Dnstap.KeyFile = ""
	c.Collectors.Dnstap.QueryTimeout = 5
	c.Collectors.Dnstap.CacheSupport = false
	c.Collectors.Dnstap.QuietText = false

	c.Collectors.DnsSniffer.Enable = false
	c.Collectors.DnsSniffer.Port = 53
	c.Collectors.DnsSniffer.Device = ""
	c.Collectors.DnsSniffer.CaptureDnsQueries = true
	c.Collectors.DnsSniffer.CaptureDnsReplies = true
	c.Collectors.DnsSniffer.QueryTimeout = 5
	c.Collectors.DnsSniffer.CacheSupport = true

	c.Collectors.PowerDNS.Enable = false
	c.Collectors.PowerDNS.ListenIP = "0.0.0.0"
	c.Collectors.PowerDNS.ListenPort = 6001
	c.Collectors.PowerDNS.QuietText = false
	c.Collectors.PowerDNS.TlsSupport = false
	c.Collectors.PowerDNS.CertFile = ""
	c.Collectors.PowerDNS.KeyFile = ""

	// Transformers
	c.Transformers.UserPrivacy.AnonymizeIP = false
	c.Transformers.UserPrivacy.MinimazeQname = false

	c.Transformers.Normalize.QnameLowerCase = false

	c.Transformers.Filtering.DropFqdnFile = ""
	c.Transformers.Filtering.DropDomainFile = ""
	c.Transformers.Filtering.DropQueryIpFile = ""
	c.Transformers.Filtering.DropRcodes = []string{}
	c.Transformers.Filtering.LogQueries = true
	c.Transformers.Filtering.LogReplies = true

	c.Transformers.GeoIP.DbCountryFile = ""
	c.Transformers.GeoIP.DbCityFile = ""
	c.Transformers.GeoIP.DbAsnFile = ""

	// Loggers
	c.Loggers.Stdout.Enable = false
	c.Loggers.Stdout.Mode = "text"
	c.Loggers.Stdout.TextFormat = ""

	c.Loggers.Dnstap.Enable = false
	c.Loggers.Dnstap.RemoteAddress = "127.0.0.1"
	c.Loggers.Dnstap.RemotePort = 6000
	c.Loggers.Dnstap.RetryInterval = 5
	c.Loggers.Dnstap.SockPath = ""
	c.Loggers.Dnstap.TlsSupport = false
	c.Loggers.Dnstap.TlsInsecure = false
	c.Loggers.Dnstap.ServerId = ""

	c.Loggers.LogFile.Enable = false
	c.Loggers.LogFile.FilePath = ""
	c.Loggers.LogFile.FlushInterval = 10
	c.Loggers.LogFile.MaxSize = 100
	c.Loggers.LogFile.MaxFiles = 10
	c.Loggers.LogFile.Compress = false
	c.Loggers.LogFile.CompressInterval = 60
	c.Loggers.LogFile.CompressPostCommand = ""
	c.Loggers.LogFile.Mode = "text"
	c.Loggers.LogFile.PostRotateCommand = ""
	c.Loggers.LogFile.PostRotateDelete = false
	c.Loggers.LogFile.TextFormat = ""

	c.Loggers.Prometheus.Enable = false
	c.Loggers.Prometheus.ListenIP = "127.0.0.1"
	c.Loggers.Prometheus.ListenPort = 8081
	c.Loggers.Prometheus.BasicAuthLogin = "admin"
	c.Loggers.Prometheus.BasicAuthPwd = "changeme"
	c.Loggers.Prometheus.TlsSupport = false
	c.Loggers.Prometheus.TlsMutual = false
	c.Loggers.Prometheus.CertFile = ""
	c.Loggers.Prometheus.KeyFile = ""
	c.Loggers.Prometheus.PromPrefix = "dnscollectorv2"
	c.Loggers.Prometheus.TopN = 10

	c.Loggers.WebServer.Enable = false
	c.Loggers.WebServer.ListenIP = "127.0.0.1"
	c.Loggers.WebServer.ListenPort = 8080
	c.Loggers.WebServer.BasicAuthLogin = "admin"
	c.Loggers.WebServer.BasicAuthPwd = "changeme"
	c.Loggers.WebServer.TlsSupport = false
	c.Loggers.WebServer.CertFile = ""
	c.Loggers.WebServer.KeyFile = ""
	c.Loggers.WebServer.PromPrefix = "dnscollector"
	c.Loggers.WebServer.StatsTopMaxItems = 100
	c.Loggers.WebServer.StatsThresholdQnameLen = 80
	c.Loggers.WebServer.StatsThresholdPacketLen = 1000
	c.Loggers.WebServer.StatsThresholdSlow = 0.5
	c.Loggers.WebServer.StatsCommonQtypes = []string{"A", "AAAA", "TXT", "CNAME", "PTR", "NAPTR", "DNSKEY", "SRV", "SOA", "NS", "MX", "DS"}

	c.Loggers.TcpClient.Enable = false
	c.Loggers.TcpClient.RemoteAddress = "127.0.0.1"
	c.Loggers.TcpClient.RemotePort = 9999
	c.Loggers.TcpClient.SockPath = ""
	c.Loggers.TcpClient.RetryInterval = 5
	c.Loggers.TcpClient.Transport = "tcp"
	c.Loggers.TcpClient.TlsSupport = false
	c.Loggers.TcpClient.TlsInsecure = false
	c.Loggers.TcpClient.Mode = "json"
	c.Loggers.TcpClient.TextFormat = ""
	c.Loggers.TcpClient.Delimiter = "\n"

	c.Loggers.Syslog.Enable = false
	c.Loggers.Syslog.Severity = "INFO"
	c.Loggers.Syslog.Facility = "DAEMON"
	c.Loggers.Syslog.Transport = "local"
	c.Loggers.Syslog.RemoteAddress = "127.0.0.1:514"
	c.Loggers.Syslog.TextFormat = ""
	c.Loggers.Syslog.Mode = "text"
	c.Loggers.Syslog.TlsSupport = false
	c.Loggers.Syslog.TlsInsecure = false

	c.Loggers.Fluentd.Enable = false
	c.Loggers.Fluentd.RemoteAddress = "127.0.0.1"
	c.Loggers.Fluentd.RemotePort = 24224
	c.Loggers.Fluentd.SockPath = ""
	c.Loggers.Fluentd.RetryInterval = 5
	c.Loggers.Fluentd.Transport = "tcp"
	c.Loggers.Fluentd.TlsSupport = false
	c.Loggers.Fluentd.TlsInsecure = false
	c.Loggers.Fluentd.Tag = "dns.collector"

	c.Loggers.PcapFile.Enable = false
	c.Loggers.PcapFile.FilePath = ""
	c.Loggers.PcapFile.MaxSize = 100
	c.Loggers.PcapFile.MaxFiles = 10
	c.Loggers.PcapFile.Compress = false
	c.Loggers.PcapFile.CompressInterval = 60
	c.Loggers.PcapFile.PostRotateCommand = ""
	c.Loggers.PcapFile.PostRotateDelete = false

	c.Loggers.InfluxDB.Enable = false
	c.Loggers.InfluxDB.ServerURL = "http://localhost:8086"
	c.Loggers.InfluxDB.AuthToken = ""
	c.Loggers.InfluxDB.TlsSupport = false
	c.Loggers.InfluxDB.TlsInsecure = false
	c.Loggers.InfluxDB.Bucket = ""
	c.Loggers.InfluxDB.Organization = ""

	c.Loggers.LokiClient.Enable = false
	c.Loggers.LokiClient.ServerURL = "http://localhost:3100/loki/api/v1/push"
	c.Loggers.LokiClient.JobName = "dnscollector"
	c.Loggers.LokiClient.Mode = "text"
	c.Loggers.LokiClient.FlushInterval = 5
	c.Loggers.LokiClient.BatchSize = 1024 * 1024
	c.Loggers.LokiClient.RetryInterval = 10
	c.Loggers.LokiClient.TextFormat = ""
	c.Loggers.LokiClient.ProxyURL = ""
	c.Loggers.LokiClient.TlsInsecure = false
	c.Loggers.LokiClient.BasicAuthLogin = ""
	c.Loggers.LokiClient.BasicAuthPwd = ""
	c.Loggers.LokiClient.TenantId = ""

	c.Loggers.Statsd.Enable = false
	c.Loggers.Statsd.Prefix = "dnscollector"
	c.Loggers.Statsd.RemoteAddress = "127.0.0.1"
	c.Loggers.Statsd.RemotePort = 8125
	c.Loggers.Statsd.Transport = "udp"
	c.Loggers.Statsd.FlushInterval = 10
	c.Loggers.Statsd.TlsSupport = false
	c.Loggers.Statsd.TlsInsecure = false
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
