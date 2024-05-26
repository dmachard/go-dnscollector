package pkgconfig

import (
	"fmt"

	"github.com/pkg/errors"
)

type ConfigPipelines struct {
	Name          string                 `yaml:"name"`
	Transforms    map[string]interface{} `yaml:"transforms"`
	Params        map[string]interface{} `yaml:",inline"`
	RoutingPolicy PipelinesRouting       `yaml:"routing-policy"`
}

func (c *ConfigPipelines) IsValid(userCfg map[string]interface{}) error {
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

	if _, ok := userCfg["routing-policy"]; ok {
		cfg := PipelinesRouting{}
		if err := cfg.IsValid(userCfg["routing-policy"].(map[string]interface{})); err != nil {
			return errors.Errorf("routing-policy - %s", err)
		}
		delete(userCfg, "routing-policy")
	}

	a := ConfigCollectors{}
	errA := a.IsValid(userCfg)
	b := ConfigLoggers{}
	errB := b.IsValid(userCfg)

	if errA != nil && errB != nil {
		return errors.Errorf("invalid stranza - %s", errA)
	}

	return nil
}

type PipelinesRouting struct {
	Forward []string `yaml:"forward,flow"`
	Dropped []string `yaml:"dropped,flow"`
}

func (c *PipelinesRouting) IsValid(userCfg map[string]interface{}) error {
	for k := range userCfg {
		if k != "forward" && k != "dropped" {
			return fmt.Errorf("invalid key '%s'", k)
		}
	}
	return nil
}
