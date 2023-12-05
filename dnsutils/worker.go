package dnsutils

import "github.com/dmachard/go-dnscollector/pkgconfig"

type Worker interface {
	SetLoggers(loggers []Worker)
	GetName() string
	Stop()
	Run()
	Channel() chan DNSMessage
	ReadConfig()
	ReloadConfig(config *pkgconfig.Config)
}
