//go:build windows || darwin || freebsd
// +build windows darwin freebsd

package workers

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type AfpacketSniffer struct {
	*GenericWorker
}

func NewAfpacketSniffer(next []Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Collectors.AfpacketLiveCapture.ChannelBufferSize > 0 {
		bufSize = config.Collectors.AfpacketLiveCapture.ChannelBufferSize
	}
	w := &AfpacketSniffer{GenericWorker: NewGenericWorker(config, logger, name, "AFPACKET sniffer", bufSize, pkgconfig.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *AfpacketSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}
