package pkgconfig

type ConfigGlobal struct {
	TextFormat          string `yaml:"text-format"`
	TextFormatDelimiter string `yaml:"text-format-delimiter"`
	TextFormatBoundary  string `yaml:"text-format-boundary"`
	Trace               struct {
		Verbose      bool   `yaml:"verbose"`
		LogMalformed bool   `yaml:"log-malformed"`
		Filename     string `yaml:"filename"`
		MaxSize      int    `yaml:"max-size"`
		MaxBackups   int    `yaml:"max-backups"`
	} `yaml:"trace"`
	ServerIdentity string `yaml:"server-identity"`
}
