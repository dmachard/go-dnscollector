package dnsutils

import (
	"flag"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Verbose  bool   `yaml:"verbose"`
	ServerId string `yaml:"server-id"`

	Collectors struct {
		DnstapUnix struct {
			Enable   bool   `yaml:"enable"`
			SockPath string `yaml:"sock-path"`
		} `yaml:"dnstap-unix"`
		DnstapTcp struct {
			Enable     bool   `yaml:"enable"`
			ListenIP   string `yaml:"listen-ip"`
			ListenPort int    `yaml:"listen-port"`
		} `yaml:"dnstap-tcp"`
		DnsSniffer struct {
			Enable            bool   `yaml:"enable"`
			Port              int    `yaml:"port"`
			Device            string `yaml:"device"`
			CaptureDnsQueries bool   `yaml:"capture-dns-queries"`
			CaptureDnsReplies bool   `yaml:"capture-dns-replies"`
		} `yaml:"dns-sniffer"`
	} `yaml:"collectors"`

	Processors struct {
		Filtering struct {
			IgnoreQname string `yaml:"ignore-qname"`
			LogQueries  bool   `yaml:"log-queries"`
			LogReplies  bool   `yaml:"log-replies"`
		} `yaml:"filtering"`
		GeoIP struct {
			DbFile string `yaml:"db-file"`
		} `yaml:"geoip"`
	} `yaml:"processors"`

	Generators struct {
		Stdout struct {
			Enable bool   `yaml:"enable"`
			Mode   string `yaml:"mode"`
		} `yaml:"stdout"`
		WebServer struct {
			Enable         bool   `yaml:"enable"`
			ListenIP       string `yaml:"listen-ip"`
			ListenPort     int    `yaml:"listen-port"`
			TopMaxItems    int    `yaml:"top-max-items"`
			BasicAuthLogin string `yaml:"basic-auth-login"`
			BasicAuthPwd   string `yaml:"basic-auth-pwd"`
		} `yaml:"webserver"`
		LogFile struct {
			Enable     bool   `yaml:"enable"`
			FilePath   string `yaml:"file-path"`
			MaxSize    int    `yaml:"max-size"`
			MaxFiles   int    `yaml:"max-files"`
			LogQueries bool   `yaml:"log-queries"`
			LogReplies bool   `yaml:"log-replies"`
		} `yaml:"logfile"`
		DnstapTcp struct {
			Enable        bool   `yaml:"enable"`
			RemoteIP      string `yaml:"remote-ip"`
			RemotePort    int    `yaml:"remote-port"`
			RetryInterval int    `yaml:"retry-interval"`
		} `yaml:"dnstap-tcp"`
		DnstapUnix struct {
			Enable        bool   `yaml:"enable"`
			SockPath      string `yaml:"sock-path"`
			RetryInterval int    `yaml:"retry-interval"`
		} `yaml:"dnstap-unix"`
		JsonTcp struct {
			Enable        bool   `yaml:"enable"`
			RemoteIP      string `yaml:"remote-ip"`
			RemotePort    int    `yaml:"remote-port"`
			RetryInterval int    `yaml:"retry-interval"`
		} `yaml:"json-tcp"`
	} `yaml:"generators"`
}

func (c *Config) SetDefault() {
	c.Verbose = false
	c.ServerId = ""

	c.Collectors.DnstapTcp.Enable = true
	c.Collectors.DnstapTcp.ListenIP = "0.0.0.0"
	c.Collectors.DnstapTcp.ListenPort = 6000

	c.Collectors.DnstapUnix.Enable = false
	c.Collectors.DnstapUnix.SockPath = ""

	c.Collectors.DnsSniffer.Enable = false
	c.Collectors.DnsSniffer.Port = 53
	c.Collectors.DnsSniffer.Device = ""
	c.Collectors.DnsSniffer.CaptureDnsQueries = true
	c.Collectors.DnsSniffer.CaptureDnsReplies = true

	c.Processors.Filtering.IgnoreQname = ""
	c.Processors.Filtering.LogQueries = true
	c.Processors.Filtering.LogReplies = true
	c.Processors.GeoIP.DbFile = ""

	c.Generators.Stdout.Enable = true
	c.Generators.Stdout.Mode = "text"

	c.Generators.DnstapTcp.Enable = false
	c.Generators.DnstapTcp.RemoteIP = "127.0.0.1"
	c.Generators.DnstapTcp.RemotePort = 6000
	c.Generators.DnstapTcp.RetryInterval = 5

	c.Generators.DnstapUnix.Enable = false
	c.Generators.DnstapUnix.SockPath = ""
	c.Generators.DnstapUnix.RetryInterval = 5

	c.Generators.LogFile.Enable = false
	c.Generators.LogFile.FilePath = ""
	c.Generators.LogFile.LogQueries = true
	c.Generators.LogFile.LogReplies = true
	c.Generators.LogFile.MaxSize = 1
	c.Generators.LogFile.MaxFiles = 1

	c.Generators.WebServer.Enable = false
	c.Generators.WebServer.ListenIP = "127.0.0.1"
	c.Generators.WebServer.ListenPort = 8080
	c.Generators.WebServer.TopMaxItems = 100
	c.Generators.WebServer.BasicAuthLogin = "admin"
	c.Generators.WebServer.BasicAuthPwd = "changeme"

	c.Generators.JsonTcp.Enable = false
	c.Generators.JsonTcp.RemoteIP = "127.0.0.1"
	c.Generators.JsonTcp.RemotePort = 9999
	c.Generators.JsonTcp.RetryInterval = 5
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
