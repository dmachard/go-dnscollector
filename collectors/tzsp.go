//go:build windows || freebsd || darwin
// +build windows freebsd darwin

package collectors

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type TZSPSniffer struct {
	*pkgutils.GenericWorker
}

func NewTZSP(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *TZSPSniffer {
	s := &TZSPSniffer{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "tzsp", pkgutils.DefaultBufferSize)}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
}

func (c *TZSPSniffer) StartCollect() {
	c.LogError("running collector failed...OS not supported!")
	defer c.CollectDone()
}
