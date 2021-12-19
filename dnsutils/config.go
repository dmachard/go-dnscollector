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

type Config struct {
	Trace struct {
		Verbose    bool   `yaml:"verbose"`
		Filename   string `yaml:"filename"`
		MaxSize    int    `yaml:"max-size"`
		MaxBackups int    `yaml:"max-backups"`
	} `yaml:"trace"`

	Collectors struct {
		Tail struct {
			Enable       bool   `yaml:"enable"`
			TimeLayout   string `yaml:"time-layout"`
			PatternQuery string `yaml:"pattern-query"`
			PatternReply string `yaml:"pattern-reply"`
			FilePath     string `yaml:"file-path"`
		} `yaml:"tail"`
		Dnstap struct {
			Enable     bool   `yaml:"enable"`
			ListenIP   string `yaml:"listen-ip"`
			ListenPort int    `yaml:"listen-port"`
			SockPath   string `yaml:"sock-path"`
			TlsSupport bool   `yaml:"tls-support"`
			CertFile   string `yaml:"cert-file"`
			KeyFile    string `yaml:"key-file"`
		} `yaml:"dnstap"`
		DnsSniffer struct {
			Enable            bool   `yaml:"enable"`
			Port              int    `yaml:"port"`
			Device            string `yaml:"device"`
			CaptureDnsQueries bool   `yaml:"capture-dns-queries"`
			CaptureDnsReplies bool   `yaml:"capture-dns-replies"`
		} `yaml:"dns-sniffer"`
	} `yaml:"collectors"`

	Subprocessors struct {
		DnstapQuietText bool `yaml:"dnstap-quiet-text"`
		Statistics      struct {
			TopMaxItems        int      `yaml:"top-max-items"`
			ThresholdQnameLen  int      `yaml:"threshold-qname-len"`
			ThresholdPacketLen int      `yaml:"threshold-packet-len"`
			ThresholdSlow      float64  `yaml:"threshold-slow"`
			CommonQtypes       []string `yaml:"common-qtypes,flow"`
		} `yaml:"statistics"`
		AnonymizeIP    bool `yaml:"anonymize-ip"`
		QnameLowerCase bool `yaml:"qname-lowercase"`
		Cache          struct {
			Enable bool `yaml:"enable"`
			Ttl    int  `yaml:"ttl"`
		} `yaml:"cache"`
		ServerId  string `yaml:"server-id"`
		Filtering struct {
			DropFqdnFile   string `yaml:"drop-fqdn-file"`
			DropDomainFile string `yaml:"drop-domain-file"`
			LogQueries     bool   `yaml:"log-queries"`
			LogReplies     bool   `yaml:"log-replies"`
		} `yaml:"filtering"`
		GeoIP struct {
			DbFile string `yaml:"db-file"`
		} `yaml:"geoip"`
		TextFormat string `yaml:"text-format"`
	} `yaml:"subprocessors"`

	Loggers struct {
		Stdout struct {
			Enable     bool   `yaml:"enable"`
			Mode       string `yaml:"mode"`
			TextFormat string `yaml:"text-format"`
		} `yaml:"stdout"`
		WebServer struct {
			Enable         bool   `yaml:"enable"`
			ListenIP       string `yaml:"listen-ip"`
			ListenPort     int    `yaml:"listen-port"`
			BasicAuthLogin string `yaml:"basic-auth-login"`
			BasicAuthPwd   string `yaml:"basic-auth-pwd"`
			TlsSupport     bool   `yaml:"tls-support"`
			CertFile       string `yaml:"cert-file"`
			KeyFile        string `yaml:"key-file"`
			PromPrefix     string `yaml:"prometheus-prefix"`
		} `yaml:"webserver"`
		LogFile struct {
			Enable            bool   `yaml:"enable"`
			FilePath          string `yaml:"file-path"`
			MaxSize           int    `yaml:"max-size"`
			MaxFiles          int    `yaml:"max-files"`
			FlushInterval     int    `yaml:"flush-interval"`
			Compress          bool   `yaml:"compress"`
			CompressInterval  int    `yaml:"compress-interval"`
			Mode              string `yaml:"mode"`
			PostRotateCommand string `yaml:"postrotate-command"`
			PostRotateDelete  bool   `yaml:"postrotate-delete-success"`
			TextFormat        string `yaml:"text-format"`
		} `yaml:"logfile"`
		Dnstap struct {
			Enable        bool   `yaml:"enable"`
			RemoteAddress string `yaml:"remote-address"`
			RemotePort    int    `yaml:"remote-port"`
			SockPath      string `yaml:"sock-path"`
			RetryInterval int    `yaml:"retry-interval"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
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
			Enable        bool   `yaml:"enable"`
			ServerURL     string `yaml:"server-url"`
			JobName       string `yaml:"job-name"`
			FlushInterval int    `yaml:"flush-interval"`
			BufferSize    int    `yaml:"buffer-size"`
			RetryInterval int    `yaml:"retry-interval"`
			TextFormat    string `yaml:"text-format"`
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
}

func (c *Config) SetDefault() {

	c.Trace.Verbose = false
	c.Trace.Filename = ""
	c.Trace.MaxSize = 10
	c.Trace.MaxBackups = 10

	// Collectors
	c.Collectors.Tail.Enable = false
	c.Collectors.Tail.TimeLayout = ""
	c.Collectors.Tail.PatternQuery = ""
	c.Collectors.Tail.PatternReply = ""
	c.Collectors.Tail.FilePath = ""

	c.Collectors.Dnstap.Enable = true
	c.Collectors.Dnstap.ListenIP = "0.0.0.0"
	c.Collectors.Dnstap.ListenPort = 6000
	c.Collectors.Dnstap.SockPath = ""
	c.Collectors.Dnstap.TlsSupport = false
	c.Collectors.Dnstap.CertFile = ""
	c.Collectors.Dnstap.KeyFile = ""

	c.Collectors.DnsSniffer.Enable = false
	c.Collectors.DnsSniffer.Port = 53
	c.Collectors.DnsSniffer.Device = ""
	c.Collectors.DnsSniffer.CaptureDnsQueries = true
	c.Collectors.DnsSniffer.CaptureDnsReplies = true

	// Subprocessors
	c.Subprocessors.DnstapQuietText = false

	c.Subprocessors.Statistics.TopMaxItems = 100
	c.Subprocessors.Statistics.ThresholdQnameLen = 80
	c.Subprocessors.Statistics.ThresholdPacketLen = 1000
	c.Subprocessors.Statistics.ThresholdSlow = 0.5
	c.Subprocessors.Statistics.CommonQtypes = []string{"A", "AAAA", "TXT", "CNAME", "PTR", "NAPTR", "DNSKEY", "SRV", "SOA", "NS", "MX", "DS"}

	c.Subprocessors.AnonymizeIP = false

	c.Subprocessors.QnameLowerCase = true

	c.Subprocessors.Cache.Ttl = 10
	c.Subprocessors.Cache.Enable = true

	c.Subprocessors.ServerId = ""

	c.Subprocessors.Filtering.DropFqdnFile = ""
	c.Subprocessors.Filtering.DropDomainFile = ""
	c.Subprocessors.Filtering.LogQueries = true
	c.Subprocessors.Filtering.LogReplies = true

	c.Subprocessors.GeoIP.DbFile = ""
	c.Subprocessors.TextFormat = "timestamp identity operation rcode queryip queryport family protocol length qname qtype latency"

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

	c.Loggers.LogFile.Enable = false
	c.Loggers.LogFile.FilePath = ""
	c.Loggers.LogFile.FlushInterval = 10
	c.Loggers.LogFile.MaxSize = 100
	c.Loggers.LogFile.MaxFiles = 10
	c.Loggers.LogFile.Compress = false
	c.Loggers.LogFile.CompressInterval = 60
	c.Loggers.LogFile.Mode = "text"
	c.Loggers.LogFile.PostRotateCommand = ""
	c.Loggers.LogFile.PostRotateDelete = false
	c.Loggers.LogFile.TextFormat = ""

	c.Loggers.WebServer.Enable = false
	c.Loggers.WebServer.ListenIP = "127.0.0.1"
	c.Loggers.WebServer.ListenPort = 8080
	c.Loggers.WebServer.BasicAuthLogin = "admin"
	c.Loggers.WebServer.BasicAuthPwd = "changeme"
	c.Loggers.WebServer.TlsSupport = false
	c.Loggers.WebServer.CertFile = ""
	c.Loggers.WebServer.KeyFile = ""
	c.Loggers.WebServer.PromPrefix = "dnscollector"

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
	c.Loggers.TcpClient.TlsSupport = false
	c.Loggers.TcpClient.TlsInsecure = false

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
	c.Loggers.LokiClient.FlushInterval = 5
	c.Loggers.LokiClient.BufferSize = 1024 * 1024
	c.Loggers.LokiClient.RetryInterval = 10
	c.Loggers.LokiClient.TextFormat = ""

	c.Loggers.Statsd.Enable = false
	c.Loggers.Statsd.Prefix = "dnscollector"
	c.Loggers.Statsd.RemoteAddress = "127.0.0.1"
	c.Loggers.Statsd.RemotePort = 8125
	c.Loggers.Statsd.Transport = "udp"
	c.Loggers.Statsd.FlushInterval = 10
	c.Loggers.Statsd.TlsSupport = false
	c.Loggers.Statsd.TlsInsecure = false
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
