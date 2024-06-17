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
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Collectors.XdpLiveCapture.ChannelBufferSize > 0 {
		bufSize = config.Collectors.XdpLiveCapture.ChannelBufferSize
	}
	w := &XDPSniffer{GenericWorker: NewGenericWorker(config, logger, name, "xdp sniffer", bufSize, pkgconfig.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *XDPSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}
