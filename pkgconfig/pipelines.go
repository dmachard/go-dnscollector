package pkgconfig

type ConfigPipelines struct {
	Name          string                 `yaml:"name"`
	Transforms    map[string]interface{} `yaml:"transforms"`
	Params        map[string]interface{} `yaml:",inline"`
	RoutingPolicy PipelinesRouting       `yaml:"routing-policy"`
}

type PipelinesRouting struct {
	Default []string `yaml:"default,flow"`
	Dropped []string `yaml:"dropped,flow"`
}
