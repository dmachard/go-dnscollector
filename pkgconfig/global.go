package pkgconfig

import (
	"reflect"

	"github.com/creasty/defaults"
)

type ConfigGlobal struct {
	TextFormat          string `yaml:"text-format" default:"timestamp identity operation rcode queryip queryport family protocol length-unit qname qtype latency"`
	TextFormatDelimiter string `yaml:"text-format-delimiter" default:" "`
	TextFormatBoundary  string `yaml:"text-format-boundary" default:"\""`
	TextJinja           string `yaml:"text-jinja" default:""`
	Trace               struct {
		Verbose      bool   `yaml:"verbose" default:"false"`
		LogMalformed bool   `yaml:"log-malformed" default:"false"`
		Filename     string `yaml:"filename" default:""`
		MaxSize      int    `yaml:"max-size" default:"10"`
		MaxBackups   int    `yaml:"max-backups" default:"10"`
	} `yaml:"trace"`
	ServerIdentity string `yaml:"server-identity" default:""`
	PidFile        string `yaml:"pid-file" default:""`
	Worker         struct {
		InternalMonitor   int `yaml:"interval-monitor" default:"10"`
		ChannelBufferSize int `yaml:"buffer-size" default:"8192"`
	} `yaml:"worker"`
	Telemetry struct {
		Enabled         bool   `yaml:"enabled" default:"false"`
		WebPath         string `yaml:"web-path" default:"/metrics"`
		WebListen       string `yaml:"web-listen" default:":9165"`
		PromPrefix      string `yaml:"prometheus-prefix" default:"dnscollector_exporter"`
		TLSSupport      bool   `yaml:"tls-support" default:"false"`
		TLSCertFile     string `yaml:"tls-cert-file" default:""`
		TLSKeyFile      string `yaml:"tls-key-file" default:""`
		ClientCAFile    string `yaml:"client-ca-file" default:""`
		BasicAuthEnable bool   `yaml:"basic-auth-enable" default:"false"`
		BasicAuthLogin  string `yaml:"basic-auth-login" default:"admin"`
		BasicAuthPwd    string `yaml:"basic-auth-pwd" default:"changeme"`
	} `yaml:"telemetry"`
}

func (c *ConfigGlobal) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigGlobal) Check(userCfg map[string]interface{}) error {
	return CheckConfigWithTags(reflect.ValueOf(*c), userCfg)
}
