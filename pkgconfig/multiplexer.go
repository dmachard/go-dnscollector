package pkgconfig

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

type MultiplexInOut struct {
	Name       string                 `yaml:"name"`
	Transforms map[string]interface{} `yaml:"transforms"`
	Params     map[string]interface{} `yaml:",inline"`
}

type MultiplexRoutes struct {
	Src []string `yaml:"from,flow"`
	Dst []string `yaml:"to,flow"`
}
