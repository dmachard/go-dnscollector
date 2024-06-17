//go:build windows || freebsd || darwin
// +build windows freebsd darwin

package workers

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type TZSPSniffer struct {
	*GenericWorker
}

func NewTZSP(next []Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *TZSPSniffer {
	w := &TZSPSniffer{GenericWorker: NewGenericWorker(config, logger, name, "tzsp", pkgconfig.DefaultBufferSize, pkgconfig.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *TZSPSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}
