package pkgconfig

import (
	"github.com/pkg/errors"
)

type ConfigMultiplexer struct {
	Collectors []MultiplexInOut  `yaml:"collectors"`
	Loggers    []MultiplexInOut  `yaml:"loggers"`
	Routes     []MultiplexRoutes `yaml:"routes"`
}

func (c *ConfigMultiplexer) SetDefault() {
	c.Collectors = []MultiplexInOut{}
	c.Loggers = []MultiplexInOut{}
	c.Routes = []MultiplexRoutes{}
}

func (c *ConfigMultiplexer) IsValid(userCfg map[string]interface{}) error {
	for k, v := range userCfg {
		if k == "collectors" {
			for i, cv := range v.([]interface{}) {
				cfg := MultiplexInOut{IsCollector: true}
				if err := cfg.IsValid(cv.(map[string]interface{})); err != nil {
					return errors.Errorf("collector(index=%d) - %s", i, err)
				}
			}

		} else if k == "loggers" {
			for i, cv := range v.([]interface{}) {
				cfg := MultiplexInOut{IsCollector: false}
				if err := cfg.IsValid(cv.(map[string]interface{})); err != nil {
					return errors.Errorf("logger(index=%d) - %s", i, err)
				}
			}

		} else if k == "routes" {
			for i, cv := range v.([]interface{}) {
				cfg := MultiplexRoutes{}
				if err := cfg.IsValid(cv.(map[string]interface{})); err != nil {
					return errors.Errorf("route(index=%d) - %s", i, err)
				}
			}

		} else {
			return errors.Errorf("unknown multiplexer key=%s\n", k)
		}
	}
	return nil
}

type MultiplexInOut struct {
	Name        string                 `yaml:"name"`
	Transforms  map[string]interface{} `yaml:"transforms"`
	Params      map[string]interface{} `yaml:",inline"`
	IsCollector bool
}

func (c *MultiplexInOut) IsValid(userCfg map[string]interface{}) error {
	if _, ok := userCfg["name"]; !ok {
		return errors.Errorf("name key is required")
	}
	delete(userCfg, "name")

	if _, ok := userCfg["transforms"]; ok {
		cfg := ConfigTransformers{}
		if err := cfg.IsValid(userCfg["transforms"].(map[string]interface{})); err != nil {
			return errors.Errorf("transform - %s", err)
		}
		delete(userCfg, "transforms")
	}

	var err error
	if c.IsCollector {
		cfg := ConfigCollectors{}
		err = cfg.IsValid(userCfg)
	} else {
		cfg := ConfigLoggers{}
		err = cfg.IsValid(userCfg)
	}

	return err
}

type MultiplexRoutes struct {
	Src []string `yaml:"from,flow"`
	Dst []string `yaml:"to,flow"`
}

func (c *MultiplexRoutes) IsValid(userCfg map[string]interface{}) error {
	if _, ok := userCfg["from"]; !ok {
		return errors.Errorf("the key 'from' is required")
	}
	if _, ok := userCfg["to"]; !ok {
		return errors.Errorf("the key 'to' is required")
	}
	return nil
}
