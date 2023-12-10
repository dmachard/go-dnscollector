package pkgconfig

type ConfigPipelines struct {
	Name       string                 `yaml:"name"`
	Transforms map[string]interface{} `yaml:"transforms"`
	Params     map[string]interface{} `yaml:",inline"`
	Routes     []string               `yaml:"routes,flow"`
}
