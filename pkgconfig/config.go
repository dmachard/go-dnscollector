package pkgconfig

import (
	"io"
	"os"
	"reflect"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
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

func ReloadConfig(configPath string, config *Config) error {
	// Open config file
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer configFile.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(configFile)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return err
	}
	return nil
}

func LoadConfig(configPath string) (*Config, error) {
	// Open config file
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	// Check config to detect unknown keywords
	if err := CheckConfig(configPath); err != nil {
		return nil, err
	}

	// Init new YAML decode
	d := yaml.NewDecoder(configFile)

	// Start YAML decoding to go
	config := &Config{}
	config.SetDefault()

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func CheckConfig(userConfigPath string) error {
	// create default config
	// and simulate one route, one collector and one logger
	defaultConfig := &Config{}
	defaultConfig.SetDefault()
	defaultConfig.Multiplexer.Routes = append(defaultConfig.Multiplexer.Routes, MultiplexRoutes{})
	defaultConfig.Multiplexer.Loggers = append(defaultConfig.Multiplexer.Loggers, MultiplexInOut{})
	defaultConfig.Multiplexer.Collectors = append(defaultConfig.Multiplexer.Collectors, MultiplexInOut{})

	// Convert default config to map
	// And get unique YAML keys
	defaultConfigMap, err := convertConfigToMap(defaultConfig)
	if err != nil {
		return errors.Wrap(err, "error converting default config to map")
	}
	defaultKeywords := getUniqueKeywords(defaultConfigMap)

	// Read user configuration file
	// And get unique YAML keys from user config
	userConfigMap, err := loadUserConfigToMap(userConfigPath)
	if err != nil {
		return err
	}
	userKeywords := getUniqueKeywords(userConfigMap)

	// Check for unknown keys in user config
	for key := range userKeywords {
		if _, ok := defaultKeywords[key]; !ok {
			return errors.Errorf("unknown YAML key `%s` in configuration", key)
		}
	}

	return nil
}

func convertConfigToMap(config *Config) (map[string]interface{}, error) {
	// Convert config to YAML
	yamlData, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}

	// Convert YAML to map
	configMap := make(map[string]interface{})
	err = yaml.Unmarshal(yamlData, &configMap)
	if err != nil {
		return nil, err
	}

	return configMap, nil
}

func loadUserConfigToMap(configPath string) (map[string]interface{}, error) {
	// Read user configuration file
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	// Read config file bytes
	configBytes, err := io.ReadAll(configFile)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading configuration file")
	}

	// Unmarshal YAML to map
	userConfigMap := make(map[string]interface{})
	err = yaml.Unmarshal(configBytes, &userConfigMap)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing YAML file")
	}

	return userConfigMap, nil
}

func getUniqueKeywords(s map[string]interface{}) map[string]bool {
	keys := extractYamlKeys(s)
	uniqueKeys := make(map[string]bool)
	for _, key := range keys {
		if _, ok := uniqueKeys[key]; ok {
			continue
		}
		uniqueKeys[key] = true
	}
	return uniqueKeys
}

func extractYamlKeys(s map[string]interface{}) []string {
	keys := []string{}
	for k, v := range s {
		keys = append(keys, k)
		val := reflect.ValueOf(v)
		if val.Kind() == reflect.Map {
			nextKeys := extractYamlKeys(val.Interface().(map[string]interface{}))
			keys = append(keys, nextKeys...)
		}
		if val.Kind() == reflect.Slice {
			for _, v2 := range val.Interface().([]interface{}) {
				val2 := reflect.ValueOf(v2)
				if val2.Kind() == reflect.Map {
					nextKeys := extractYamlKeys(val2.Interface().(map[string]interface{}))
					keys = append(keys, nextKeys...)
				}
			}
		}

	}
	return keys
}

func GetFakeConfig() *Config {
	config := &Config{}
	config.SetDefault()
	return config
}
