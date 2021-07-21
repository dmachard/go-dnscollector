package generators

import (
	"testing"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

func TestMetricsRun(t *testing.T) {
	config := &common.Config{}
	logger := logger.New(false)

	dm := dnsmessage.DnsMessage{}
	dm.Init()
	dm.Type = "query"

	// init generator in testing mode
	g := NewMetrics(config, logger)
	g.testing = true

	// send dns message in the channel and run-it
	g.Channel() <- dm
	g.Run()

	counters := g.stats.Get()
	if counters.queries != 1 {
		t.Errorf("invalid metrics client - %d", counters.queries)
	}
}
