//go:build windows
// +build windows

package collectors

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type XDPSniffer struct {
	*pkgutils.Collector
}

func NewXDPSniffer(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *XDPSniffer {
	s := &XDPSniffer{Collector: pkgutils.NewCollector(config, logger, name, "XDP sniffer")}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
}

func (c *XDPSniffer) Run() {
	c.LogInfo("This OS not supported!")
	c.StopIsDone()
}
