package pkgconfig

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"

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

func ReloadConfig(configPath string, config *Config, refDNSMessage map[string]interface{}) error {
	// Open config file
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer configFile.Close()

	// Check config to detect unknown keywords
	if err := CheckConfig(configPath, refDNSMessage); err != nil {
		return err
	}

	// Init new YAML decode
	d := yaml.NewDecoder(configFile)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return err
	}
	return nil
}

func LoadConfig(configPath string, refDNSMessage map[string]interface{}) (*Config, error) {
	// Open config file
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	// Check config to detect unknown keywords
	if err := CheckConfig(configPath, refDNSMessage); err != nil {
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

func CheckConfig(userConfigPath string, dmRef map[string]interface{}) error {
	// create default config
	// and simulate items in multiplexer and pipelines mode
	defaultConfig := &Config{}
	defaultConfig.SetDefault()
	defaultConfig.Multiplexer.Routes = append(defaultConfig.Multiplexer.Routes, MultiplexRoutes{})
	defaultConfig.Multiplexer.Loggers = append(defaultConfig.Multiplexer.Loggers, MultiplexInOut{})
	defaultConfig.Multiplexer.Collectors = append(defaultConfig.Multiplexer.Collectors, MultiplexInOut{})
	defaultConfig.Pipelines = append(defaultConfig.Pipelines, ConfigPipelines{})

	// Convert default config to map
	// And get unique YAML keys
	defaultConfigMap, err := convertConfigToMap(defaultConfig)
	if err != nil {
		return errors.Wrap(err, "error converting default config to map")
	}
	defaultKeywords := getUniqueKeywords(defaultConfigMap)

	// add DNSMessage default keys
	for k := range dmRef {
		defaultKeywords[k] = true
	}

	// Read user configuration file
	// And get unique YAML keys from user config
	userConfigMap, err := loadUserConfigToMap(userConfigPath)
	if err != nil {
		return err
	}
	userKeywords := getUniqueKeywords(userConfigMap)

	// Check for unknown keys in user config
	// ignore dynamic keys as atags.tags.*: google

	// Define regular expressions to match dynamic keys
	regexPatterns := []string{`\.\*(\.)?`, `\.(\d+)(\.)?`}

	for key := range userKeywords {
		// Ignore dynamic keys that contain ".*" or .[digits].
		matched := false
		for _, pattern := range regexPatterns {
			match, _ := regexp.MatchString(pattern, key)
			if match {
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		// search in default keywords
		if _, ok := defaultKeywords[key]; !ok {
			return errors.Errorf("unknown YAML key `%s` in configuration", key)
		}
	}

	// detect bad keyword position
	err = checkKeywordsPosition(userConfigMap, defaultConfigMap, defaultConfigMap, "")
	if err != nil {
		return err
	}
	return nil
}

func checkKeywordsPosition(nextUserCfg, nextDefCfg map[string]interface{}, defaultConf map[string]interface{}, sectionName string) error {
	for k, v := range nextUserCfg {
		// Check if the key is present in the default config
		if len(nextDefCfg) > 0 {
			if _, ok := nextDefCfg[k]; !ok {
				if sectionName == "" {
					return errors.Errorf("invalid key `%s` at root", k)
				}
				return errors.Errorf("invalid key `%s` in section `%s`", k, sectionName)
			}
		}

		// If the value is a map, recursively check for invalid keywords
		// Recursive call ?
		val := reflect.ValueOf(v)
		if val.Kind() == reflect.Map {
			nextSectionName := fmt.Sprintf("%s.%s", sectionName, k)
			if err := checkKeywordsPosition(v.(map[string]interface{}), nextDefCfg[k].(map[string]interface{}), defaultConf, nextSectionName); err != nil {
				return err
			}
		}

		// If the value is a slice and we are in the multiplexer part
		// Multiplixer part is dynamic, we need specific function to check it
		if val.Kind() == reflect.Slice && sectionName == ".multiplexer" {
			if err := checkMultiplexerConfig(val, nextDefCfg[k].([]interface{}), defaultConf, k); err != nil {
				return err
			}
		}

		// If the value is a slice and we are in the pipelines part
		if val.Kind() == reflect.Slice && k == "pipelines" {
			if err := checkPipelinesConfig(val, nextDefCfg[k].([]interface{}), defaultConf, k); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkPipelinesConfig(currentVal reflect.Value, currentRef []interface{}, defaultConf map[string]interface{}, k string) error {
	refLoggers := defaultConf[KeyLoggers].(map[string]interface{})
	refCollectors := defaultConf[KeyCollectors].(map[string]interface{})
	refTransforms := defaultConf["collectors-transformers"].(map[string]interface{})

	for pos, item := range currentVal.Interface().([]interface{}) {
		valReflect := reflect.ValueOf(item)
		refItem := currentRef[0].(map[string]interface{})
		if valReflect.Kind() == reflect.Map {
			for _, key := range valReflect.MapKeys() {
				strKey := key.Interface().(string)
				mapVal := valReflect.MapIndex(key)

				if _, ok := refItem[strKey]; !ok {
					// Check if the key exists in neither loggers nor collectors
					loggerExists := refLoggers[strKey] != nil
					collectorExists := refCollectors[strKey] != nil
					if !loggerExists && !collectorExists {
						return errors.Errorf("invalid `%s` in `%s` pipelines at position %d", strKey, k, pos)
					}

					// check logger or collectors
					if loggerExists || collectorExists {
						nextSectionName := fmt.Sprintf("%s[%d].%s", k, pos, strKey)
						refMap := refLoggers
						if collectorExists {
							refMap = refCollectors
						}
						// Type assertion to check if the value is a map
						if value, ok := mapVal.Interface().(map[string]interface{}); ok {
							if err := checkKeywordsPosition(value, refMap[strKey].(map[string]interface{}), defaultConf, nextSectionName); err != nil {
								return err
							}
						} else {
							return errors.Errorf("invalid `%s` value in `%s` pipelines at position %d", strKey, k, pos)
						}
					}
				}

				// Check transforms section
				// Type assertion to check if the value is a map
				if strKey == "transforms" {
					nextSectionName := fmt.Sprintf("%s.%s", k, strKey)
					if value, ok := mapVal.Interface().(map[string]interface{}); ok {
						if err := checkKeywordsPosition(value, refTransforms, defaultConf, nextSectionName); err != nil {
							return err
						}
					} else {
						return errors.Errorf("invalid `%s` value in `%s` pipelines at position %d", strKey, k, pos)
					}
				}
			}
		} else {
			return errors.Errorf("invalid item type in pipelines list: %s", valReflect.Kind())
		}
	}
	return nil
}

func checkMultiplexerConfig(currentVal reflect.Value, currentRef []interface{}, defaultConf map[string]interface{}, k string) error {
	refLoggers := defaultConf[KeyLoggers].(map[string]interface{})
	refCollectors := defaultConf[KeyCollectors].(map[string]interface{})
	refTransforms := defaultConf["collectors-transformers"].(map[string]interface{})

	// iter over the slice
	for pos, item := range currentVal.Interface().([]interface{}) {
		valReflect := reflect.ValueOf(item)
		refItem := currentRef[0].(map[string]interface{})
		if valReflect.Kind() == reflect.Map {
			for _, key := range valReflect.MapKeys() {
				strKey := key.Interface().(string)
				mapVal := valReflect.MapIndex(key)

				// First, check in the initial configuration reference.
				// If not found, then look in the logger and collector references.
				if _, ok := refItem[strKey]; !ok {
					// we are in routes section ?
					if !(k == KeyCollectors || k == KeyLoggers) {
						return errors.Errorf("invalid `%s` in `%s` list at position %d", strKey, k, pos)
					}

					// Check if the key exists in neither loggers nor collectors
					loggerExists := refLoggers[strKey] != nil
					collectorExists := refCollectors[strKey] != nil
					if !loggerExists && !collectorExists {
						return errors.Errorf("invalid `%s` in `%s` list at position %d", strKey, k, pos)
					}

					// check logger or collectors
					if k == KeyLoggers || k == KeyCollectors {
						nextSectionName := fmt.Sprintf("%s[%d].%s", k, pos, strKey)
						refMap := refLoggers
						if k == KeyCollectors {
							refMap = refCollectors
						}

						// Type assertion to check if the value is a map
						if value, ok := mapVal.Interface().(map[string]interface{}); ok {
							if err := checkKeywordsPosition(value, refMap[strKey].(map[string]interface{}), defaultConf, nextSectionName); err != nil {
								return err
							}
						} else {
							return errors.Errorf("invalid `%s` value in `%s` list at position %d", strKey, k, pos)
						}
					}
				}

				// Check transforms section
				// Type assertion to check if the value is a map
				if strKey == "transforms" {
					nextSectionName := fmt.Sprintf("%s.%s", k, strKey)
					if value, ok := mapVal.Interface().(map[string]interface{}); ok {
						if err := checkKeywordsPosition(value, refTransforms, defaultConf, nextSectionName); err != nil {
							return err
						}
					} else {
						return errors.Errorf("invalid `%s` value in `%s` list at position %d", strKey, k, pos)
					}
				}
			}
		} else {
			return errors.Errorf("invalid item type in multiplexer list: %s", valReflect.Kind())
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
