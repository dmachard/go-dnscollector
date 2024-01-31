package pkgconfig

import (
	"os"
)

func IsValidMode(mode string) bool {
	switch mode {
	case
		ModeText,
		ModeJSON,
		ModeFlatJSON:
		return true
	}
	return false
}

type Config struct {
	Global               ConfigGlobal       `yaml:"global"`
	Collectors           ConfigCollectors   `yaml:"collectors"`
	IngoingTransformers  ConfigTransformers `yaml:"collectors-transformers"`
	Loggers              ConfigLoggers      `yaml:"loggers"`
	OutgoingTransformers ConfigTransformers `yaml:"loggers-transformers"`
	Multiplexer          ConfigMultiplexer  `yaml:"multiplexer"`
	Pipelines            []ConfigPipelines  `yaml:"pipelines"`
}

func (c *Config) SetDefault() {
	// Set default config for global part
	c.Global.SetDefault()

	// Set default config for multiplexer
	c.Multiplexer.SetDefault()

	// sSet default config for collectors
	c.Collectors.SetDefault()

	// transformers for collectors
	c.IngoingTransformers.SetDefault()

	// Set default config for loggers
	c.Loggers.SetDefault()

	// Transformers for loggers
	c.OutgoingTransformers.SetDefault()
}

func (c *Config) GetServerIdentity() string {
	if len(c.Global.ServerIdentity) > 0 {
		return c.Global.ServerIdentity
	} else {
		hostname, err := os.Hostname()
		if err == nil {
			return hostname
		} else {
			return "undefined"
		}
	}
}

func GetFakeConfig() *Config {
	config := &Config{}
	config.SetDefault()
	return config
}
