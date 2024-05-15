//go:build linux
// +build linux

package workers

import (
	"log"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestAfpacketSnifferRun(t *testing.T) {
	g := GetWorkerForTest(pkgconfig.DefaultBufferSize)
	c := NewAfpacketSniffer([]Worker{g}, pkgconfig.GetDefaultConfig(), logger.New(false), "test")
	if err := c.Listen(); err != nil {
		log.Fatal("collector sniffer listening error: ", err)
	}
	go c.StartCollect()

	// send dns query
	net.LookupIP(pkgconfig.ProgQname)

	// waiting message in channel
	for {
		msg := <-g.GetInputChannel()
		if msg.DNSTap.Operation == dnsutils.DNSTapClientQuery && msg.DNS.Qname == pkgconfig.ProgQname {
			break
		}
	}
}
