package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_FileIngestor_Pcap(t *testing.T) {
	g := GetWorkerForTest(pkgconfig.DefaultBufferSize)
	config := pkgconfig.GetDefaultConfig()

	// watch tests data folder
	config.Collectors.FileIngestor.WatchDir = "./../testsdata/pcap/"

	// init collector
	c := NewFileIngestor([]Worker{g}, config, logger.New(false), "test")
	go c.StartCollect()

	// waiting message in channel
	for {
		// read dns message from channel
		msg := <-g.GetInputChannel()

		// check qname
		if msg.DNSTap.Operation == dnsutils.DNSTapClientQuery {
			break
		}
	}
}
