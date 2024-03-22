//go:build linux
// +build linux

package collectors

import (
	"log"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

func TestAfpacketSnifferRun(t *testing.T) {
	g := pkgutils.NewFakeLogger()
	c := NewAfpacketSniffer([]pkgutils.Worker{g}, pkgconfig.GetFakeConfig(), logger.New(false), "test")
	if err := c.Listen(); err != nil {
		log.Fatal("collector sniffer listening error: ", err)
	}
	go c.Run()

	// send dns query
	net.LookupIP("dns.collector")

	// waiting message in channel
	for {
		msg := <-g.GetInputChannel()
		if msg.DNSTap.Operation == dnsutils.DNSTapClientQuery && msg.DNS.Qname == "dns.collector" {
			break
		}
	}
}
