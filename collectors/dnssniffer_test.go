//go:build !macos
// +build !macos

package collectors

import (
	"log"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-logger"
)

func TestDnsSnifferRun(t *testing.T) {
	g := loggers.NewFakeLogger()
	c := NewDnsSniffer([]dnsutils.Worker{g}, dnsutils.GetFakeConfig(), logger.New(false))
	if err := c.Listen(); err != nil {
		log.Fatal("collector sniffer listening error: ", err)
	}
	go c.Run()

	// send dns query
	net.LookupIP("dns.collector")

	// waiting message in channel
	for {
		msg := <-g.Channel()
		if msg.DnsTap.Operation == "CLIENT_QUERY" && msg.DNS.Qname == "dns.collector" {
			break
		}
	}
}
