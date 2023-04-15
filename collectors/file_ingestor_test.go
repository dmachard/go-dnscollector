package collectors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-logger"
)

func Test_FileIngestor_Pcap(t *testing.T) {
	g := loggers.NewFakeLogger()
	config := dnsutils.GetFakeConfig()

	// watch tests data folder
	config.Collectors.FileIngestor.WatchDir = "./../testsdata/pcap/"

	// init collector
	c := NewFileIngestor([]dnsutils.Worker{g}, config, logger.New(false), "test")
	go c.Run()

	// waiting message in channel
	for {
		// read dns message from channel
		msg := <-g.Channel()

		// check qname
		if msg.DnsTap.Operation == dnsutils.DNSTAP_CLIENT_QUERY {
			break
		}
	}
}
