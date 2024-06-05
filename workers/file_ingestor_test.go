package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_FileIngestor(t *testing.T) {
	tests := []struct {
		name      string
		watchMode string
		watchDir  string
	}{
		{
			name:      "Pcap",
			watchMode: "pcap",
			watchDir:  "./../tests/testsdata/pcap/",
		},
		{
			name:      "Dnstap",
			watchMode: "dnstap",
			watchDir:  "./../tests/testsdata/dnstap/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GetWorkerForTest(pkgconfig.DefaultBufferSize)
			config := pkgconfig.GetDefaultConfig()

			// watch tests data folder
			config.Collectors.FileIngestor.WatchMode = tt.watchMode
			config.Collectors.FileIngestor.WatchDir = tt.watchDir

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
		})
	}
}
