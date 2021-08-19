package dnsutils

import (
	"flag"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Trace struct {
		Verbose    bool   `yaml:"verbose"`
		Filename   string `yaml:"filename"`
		MaxSize    int    `yaml:"max-size"`
		MaxBackups int    `yaml:"max-backups"`
	} `yaml:"trace"`

	Collectors struct {
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
		AnonymizeIP bool   `yaml:"anonymize-ip"`
		CacheTtl    int    `yaml:"cache-ttl"`
		ServerId    string `yaml:"server-id"`
		Filtering   struct {
			IgnoreQname string `yaml:"ignore-qname"`
			LogQueries  bool   `yaml:"log-queries"`
			LogReplies  bool   `yaml:"log-replies"`
		} `yaml:"filtering"`
		GeoIP struct {
			DbFile string `yaml:"db-file"`
		} `yaml:"geoip"`
	} `yaml:"subprocessors"`

	Loggers struct {
		Stdout struct {
			Enable bool   `yaml:"enable"`
			Mode   string `yaml:"mode"`
		} `yaml:"stdout"`
		WebServer struct {
			Enable           bool   `yaml:"enable"`
			ListenIP         string `yaml:"listen-ip"`
			ListenPort       int    `yaml:"listen-port"`
			TopMaxItems      int    `yaml:"top-max-items"`
			BasicAuthLogin   string `yaml:"basic-auth-login"`
			BasicAuthPwd     string `yaml:"basic-auth-pwd"`
			TlsSupport       bool   `yaml:"tls-support"`
			CertFile         string `yaml:"cert-file"`
			KeyFile          string `yaml:"key-file"`
			PrometheusSuffix string `yaml:"prometheus-suffix"`
		} `yaml:"webserver"`
		LogFile struct {
			Enable        bool   `yaml:"enable"`
			FilePath      string `yaml:"file-path"`
			MaxSize       int    `yaml:"max-size"`
			MaxFiles      int    `yaml:"max-files"`
			FlushInterval int    `yaml:"flush-interval"`
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
		} `yaml:"tcpclient"`
		Syslog struct {
			Enable        bool   `yaml:"enable"`
			Severity      string `yaml:"severity"`
			Facility      string `yaml:"facility"`
			Transport     string `yaml:"transport"`
			RemoteAddress string `yaml:"remote-address"`
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
	} `yaml:"loggers"`
}

func (c *Config) SetDefault() {
	c.Trace.Verbose = false
	c.Trace.Filename = ""
	c.Trace.MaxSize = 10
	c.Trace.MaxBackups = 10

	// Collectors
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
	c.Subprocessors.AnonymizeIP = false

	c.Subprocessors.CacheTtl = 10
	c.Subprocessors.ServerId = ""

	c.Subprocessors.Filtering.IgnoreQname = ""
	c.Subprocessors.Filtering.LogQueries = true
	c.Subprocessors.Filtering.LogReplies = true

	c.Subprocessors.GeoIP.DbFile = ""

	// Loggers
	c.Loggers.Stdout.Enable = true
	c.Loggers.Stdout.Mode = "text"

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
	c.Loggers.LogFile.MaxSize = 1
	c.Loggers.LogFile.MaxFiles = 1

	c.Loggers.WebServer.Enable = false
	c.Loggers.WebServer.ListenIP = "127.0.0.1"
	c.Loggers.WebServer.ListenPort = 8080
	c.Loggers.WebServer.TopMaxItems = 100
	c.Loggers.WebServer.BasicAuthLogin = "admin"
	c.Loggers.WebServer.BasicAuthPwd = "changeme"
	c.Loggers.WebServer.TlsSupport = false
	c.Loggers.WebServer.CertFile = ""
	c.Loggers.WebServer.KeyFile = ""
	c.Loggers.WebServer.PrometheusSuffix = "dnscollector"

	c.Loggers.TcpClient.Enable = false
	c.Loggers.TcpClient.RemoteAddress = "127.0.0.1"
	c.Loggers.TcpClient.RemotePort = 9999
	c.Loggers.TcpClient.SockPath = ""
	c.Loggers.TcpClient.RetryInterval = 5
	c.Loggers.TcpClient.Transport = "tcp"
	c.Loggers.TcpClient.TlsSupport = false
	c.Loggers.TcpClient.TlsInsecure = false
	c.Loggers.TcpClient.Mode = "json"

	c.Loggers.Syslog.Enable = false
	c.Loggers.Syslog.Severity = "INFO"
	c.Loggers.Syslog.Facility = "DAEMON"
	c.Loggers.Syslog.Transport = "local"
	c.Loggers.Syslog.RemoteAddress = "127.0.0.1:514"

	c.Loggers.Fluentd.Enable = false
	c.Loggers.Fluentd.RemoteAddress = "127.0.0.1"
	c.Loggers.Fluentd.RemotePort = 24224
	c.Loggers.Fluentd.SockPath = ""
	c.Loggers.Fluentd.RetryInterval = 5
	c.Loggers.Fluentd.Transport = "tcp"
	c.Loggers.Fluentd.TlsSupport = false
	c.Loggers.Fluentd.TlsInsecure = false
	c.Loggers.Fluentd.Tag = "dns.collector"
}

func LoadConfig() (*Config, error) {
	config := &Config{}
	config.SetDefault()

	var configPath string

	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")
	flag.Parse()

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
