//go:build windows
// +build windows

package workers

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type XDPSniffer struct {
	*GenericWorker
}

func NewXDPSniffer(next []Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *XDPSniffer {
	w := &XDPSniffer{GenericWorker: NewGenericWorker(config, logger, name, "xdp sniffer", pkgconfig.DefaultBufferSize, pkgconfig.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *XDPSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}
