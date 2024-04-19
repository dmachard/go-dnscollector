package pkgutils

import (
	"io"
	"os"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

func ReloadConfig(configPath string, config *pkgconfig.Config) error {
	// Open config file
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer configFile.Close()

	// Check config to detect unknown keywords
	if err := CheckConfig(configPath); err != nil {
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

func LoadConfig(configPath string) (*pkgconfig.Config, error) {
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
	config := &pkgconfig.Config{}
	config.SetDefault()

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func CheckConfig(userConfigPath string) error {

	// Read user YAML configuration file
	userCfg, err := loadUserConfigToMap(userConfigPath)
	if err != nil {
		return err
	}

	// check the user config with the default one
	config := &pkgconfig.Config{}
	config.SetDefault()

	// check if the provided config is valid
	return config.IsValid(userCfg)
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
