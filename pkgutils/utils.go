package pkgutils

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
)

type Worker interface {
	AddDefaultRoute(wrk Worker)
	AddDroppedRoute(wrk Worker)
	SetLoggers(loggers []Worker)
	GetName() string
	Stop()
	Run()
	GetInputChannel() chan dnsutils.DNSMessage
	ReadConfig()
	ReloadConfig(config *pkgconfig.Config)
}
