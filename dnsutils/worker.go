package dnsutils

type Worker interface {
	SetLoggers(loggers []Worker)
	GetName() string
	Stop()
	Run()
	Channel() chan DnsMessage
	ReadConfig()
	ReloadConfig(config *Config)
}
