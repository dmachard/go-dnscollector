package pkgconfig

import (
	"io"
	"os"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

func ReloadConfig(configPath string, config *Config) error {
	// Open config file
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer configFile.Close()

	// Check config to detect unknown keywords
	if err := CheckConfig(configFile); err != nil {
		return err
	}

	// Init new YAML decode
	configFile.Seek(0, 0)
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
	if err := CheckConfig(configFile); err != nil {
		return nil, err
	}

	// Init new YAML decode
	configFile.Seek(0, 0)
	d := yaml.NewDecoder(configFile)

	// Start YAML decoding to go
	config := &Config{}
	config.SetDefault()

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func CheckConfig(configFile *os.File) error {
	// Read config file bytes
	configBytes, err := io.ReadAll(configFile)
	if err != nil {
		return errors.Wrap(err, "Error reading configuration file")
	}

	// Unmarshal YAML to map
	userCfg := make(map[string]interface{})
	err = yaml.Unmarshal(configBytes, &userCfg)
	if err != nil {
		return errors.Wrap(err, "error parsing YAML file")
	}

	// check the user config with the default one
	config := &Config{}
	config.SetDefault()

	// check if the provided config is valid
	return config.IsValid(userCfg)
}
