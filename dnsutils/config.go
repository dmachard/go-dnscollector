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

	Generators struct {
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
		} `yaml:"dnstap"`
		JsonTcp struct {
			Enable        bool   `yaml:"enable"`
			RemoteAddress string `yaml:"remote-address"`
			RemotePort    int    `yaml:"remote-port"`
			RetryInterval int    `yaml:"retry-interval"`
		} `yaml:"json-tcp"`
		Syslog struct {
			Enable        bool   `yaml:"enable"`
			Severity      string `yaml:"severity"`
			Facility      string `yaml:"facility"`
			Transport     string `yaml:"transport"`
			RemoteAddress string `yaml:"remote-address"`
		} `yaml:"syslog"`
	} `yaml:"generators"`
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

	// Generators
	c.Generators.Stdout.Enable = true
	c.Generators.Stdout.Mode = "text"

	c.Generators.Dnstap.Enable = false
	c.Generators.Dnstap.RemoteAddress = "127.0.0.1"
	c.Generators.Dnstap.RemotePort = 6000
	c.Generators.Dnstap.RetryInterval = 5
	c.Generators.Dnstap.SockPath = ""

	c.Generators.LogFile.Enable = false
	c.Generators.LogFile.FilePath = ""
	c.Generators.LogFile.FlushInterval = 10
	c.Generators.LogFile.MaxSize = 1
	c.Generators.LogFile.MaxFiles = 1

	c.Generators.WebServer.Enable = false
	c.Generators.WebServer.ListenIP = "127.0.0.1"
	c.Generators.WebServer.ListenPort = 8080
	c.Generators.WebServer.TopMaxItems = 100
	c.Generators.WebServer.BasicAuthLogin = "admin"
	c.Generators.WebServer.BasicAuthPwd = "changeme"
	c.Generators.WebServer.TlsSupport = false
	c.Generators.WebServer.CertFile = ""
	c.Generators.WebServer.KeyFile = ""
	c.Generators.WebServer.PrometheusSuffix = "dnscollector"

	c.Generators.JsonTcp.Enable = false
	c.Generators.JsonTcp.RemoteAddress = "127.0.0.1"
	c.Generators.JsonTcp.RemotePort = 9999
	c.Generators.JsonTcp.RetryInterval = 5

	c.Generators.Syslog.Enable = false
	c.Generators.Syslog.Severity = "INFO"
	c.Generators.Syslog.Facility = "DAEMON"
	c.Generators.Syslog.Transport = "local"
	c.Generators.Syslog.RemoteAddress = "127.0.0.1:514"
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
