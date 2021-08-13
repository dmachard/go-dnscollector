package collectors

import (
	"log"
	"net"
	"testing"

	"github.com/dmachard/go-dnslogger/dnsutils"
	"github.com/dmachard/go-dnslogger/loggers"
	"github.com/dmachard/go-logger"
)

func TestDnsSnifferRun(t *testing.T) {
	g := loggers.NewFakeGenerator()
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
		if msg.Operation == "CLIENT_QUERY" && msg.Qname == "dns.collector" {
			break
		}
	}
}
