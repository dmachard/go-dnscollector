package pkgutils

import (
	"testing"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestGenericWorker(t *testing.T) {
	NewGenericWorker(pkgconfig.GetDefaultConfig(), logger.New(false), "testonly", "", DefaultBufferSize, WorkerMonitorDisabled)
}
