package common

import (
	"flag"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Trace struct {
		Verbose bool `yaml:"verbose"`
	} `yaml:"trace"`

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
	} `yaml:"collectors"`

	Generators struct {
		Stdout struct {
			Enable bool `yaml:"enable"`
		} `yaml:"stdout"`
		Metrics struct {
			Enable      bool   `yaml:"enable"`
			ListenIP    string `yaml:"listen-ip"`
			ListenPort  int    `yaml:"listen-port"`
			TopMaxItems int    `yaml:"top-max-items"`
		} `yaml:"metrics"`
		LogFile struct {
			Enable     bool   `yaml:"enable"`
			FilePath   string `yaml:"file-path"`
			MaxSize    int    `yaml:"max-size"`
			MaxFiles   int    `yaml:"max-files"`
			LogQueries bool   `yaml:"log-queries"`
			LogReplies bool   `yaml:"log-replies"`
		} `yaml:"logfile"`
		DnstapSender struct {
			Enable         bool   `yaml:"enable"`
			RemoteIP       string `yaml:"remote-ip"`
			RemotePort     int    `yaml:"remote-port"`
			Retry          int    `yaml:"retry"`
			DnstapIdentity string `yaml:"dnstap-identity"`
		} `yaml:"dnstapsender"`
	} `yaml:"generators"`
}

func (c *Config) SetDefault() {
	c.Trace.Verbose = false

	c.Collectors.DnstapTcp.Enable = true
	c.Collectors.DnstapTcp.ListenIP = "0.0.0.0"
	c.Collectors.DnstapTcp.ListenPort = 6000

	c.Generators.Stdout.Enable = true
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
