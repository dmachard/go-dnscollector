//go:build windows || darwin || freebsd
// +build windows darwin freebsd

package workers

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type AfpacketSniffer struct {
	*pkgutils.GenericWorker
}

func NewAfpacketSniffer(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	w := &AfpacketSniffer{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "AFPACKET sniffer", pkgutils.DefaultBufferSize)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *AfpacketSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}
