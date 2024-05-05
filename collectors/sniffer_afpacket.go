//go:build windows || darwin || freebsd
// +build windows darwin freebsd

package collectors

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type AfpacketSniffer struct {
	*pkgutils.GenericWorker
}

func NewAfpacketSniffer(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	s := &AfpacketSniffer{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "AFPACKET sniffer", pkgutils.DefaultBufferSize)}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
}

func (c *AfpacketSniffer) Run() {
	c.LogError("running collector failed...OS not supported!")
	c.StopIsDone()
}
