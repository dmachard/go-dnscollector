package dnsutils

type Worker interface {
	SetLoggers(loggers []Worker)
	GetName() string
	Stop()
	Run()
	Channel() chan DNSMessage
	ReadConfig()
	ReloadConfig(config *Config)
}
