package pkgconfig

import (
	"reflect"

	"github.com/creasty/defaults"
)

type ConfigGlobal struct {
	TextFormat          string `yaml:"text-format" default:"timestamp identity operation rcode queryip queryport family protocol length-unit qname qtype latency"`
	TextFormatDelimiter string `yaml:"text-format-delimiter" default:" "`
	TextFormatBoundary  string `yaml:"text-format-boundary" default:"\""`
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
		InternalMonitor int `yaml:"interval-monitor" default:"10"`
	} `yaml:"worker"`
	Telemetry struct {
		Enabled    bool   `yaml:"enabled" default:"true"`
		WebPath    string `yaml:"web-path" default:"/metrics"`
		WebListen  string `yaml:"web-listen" default:":9165"`
		PromPrefix string `yaml:"prometheus-prefix" default:"dnscollector_exporter"`
	} `yaml:"telemetry"`
}

func (c *ConfigGlobal) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigGlobal) Check(userCfg map[string]interface{}) error {
	return CheckConfigWithTags(reflect.ValueOf(*c), userCfg)
}
