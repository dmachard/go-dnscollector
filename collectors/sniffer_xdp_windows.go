//go:build windows
// +build windows

package collectors

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type XDPSniffer struct {
	*pkgutils.GenericWorker
}

func NewXDPSniffer(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *XDPSniffer {
	s := &XDPSniffer{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "xdp sniffer", pkgutils.DefaultBufferSize)}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
}

func (c *XDPSniffer) StartCollect() {
	c.LogError("running collector failed...OS not supported!")
	defer c.CollectDone()
}
