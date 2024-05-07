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
	w := &XDPSniffer{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "xdp sniffer", pkgutils.DefaultBufferSize)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *XDPSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}
