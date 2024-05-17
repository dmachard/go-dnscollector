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
}

func (c *ConfigGlobal) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigGlobal) Check(userCfg map[string]interface{}) error {
	return CheckConfigWithTags(reflect.ValueOf(*c), userCfg)
}
