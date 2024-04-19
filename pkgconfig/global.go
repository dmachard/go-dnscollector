package pkgconfig

import (
	"reflect"
)

type ConfigGlobal struct {
	TextFormat          string `yaml:"text-format"`
	TextFormatDelimiter string `yaml:"text-format-delimiter"`
	TextFormatBoundary  string `yaml:"text-format-boundary"`
	Trace               struct {
		Verbose      bool   `yaml:"verbose"`
		LogMalformed bool   `yaml:"log-malformed"`
		Filename     string `yaml:"filename"`
		MaxSize      int    `yaml:"max-size"`
		MaxBackups   int    `yaml:"max-backups"`
	} `yaml:"trace"`
	ServerIdentity string `yaml:"server-identity"`
}

func (c *ConfigGlobal) SetDefault() {
	// global config
	c.TextFormat = "timestamp identity operation rcode queryip queryport family protocol length-unit qname qtype latency"
	c.TextFormatDelimiter = " "
	c.TextFormatBoundary = "\""

	c.Trace.Verbose = false
	c.Trace.LogMalformed = false
	c.Trace.Filename = ""
	c.Trace.MaxSize = 10
	c.Trace.MaxBackups = 10
	c.ServerIdentity = ""
}

func (c *ConfigGlobal) Check(userCfg map[string]interface{}) error {
	return CheckConfig(reflect.ValueOf(*c), userCfg)
}
