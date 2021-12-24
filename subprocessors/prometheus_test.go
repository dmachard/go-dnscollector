package subprocessors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestNewPrometheus(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfig()

	// init the processor
	prom := NewPrometheusSubprocessor(config, logger.New(false), "1.2.3")
	if prom.version != "1.2.3" {
		t.Errorf("bad version, got %s", prom.version)
	}
}
