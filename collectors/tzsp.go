//go:build windows || freebsd || darwin
// +build windows freebsd darwin

package collectors

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type TZSPSniffer struct {
	*pkgutils.Collector
}

func NewTZSP(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *TZSPSniffer {
	s := &TZSPSniffer{Collector: pkgutils.NewCollector(config, logger, name, "tzsp")}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
}
