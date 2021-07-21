package generators

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

func TestStdoutRun(t *testing.T) {
	config := &common.Config{}
	logger := logger.New(false)
	var o2 bytes.Buffer

	dm := dnsmessage.DnsMessage{}
	dm.Init()

	// init generator in testing mode
	// and redirect stdout output to bytes buffer
	g := NewStdOut(config, logger)
	g.stdoutLogger.SetOutput(&o2)
	g.testing = true

	// send dns message in the channel and run-it
	// in testing mode, the run function exist after
	// to receive one and only one message
	g.Channel() <- dm
	g.Run()

	if o2.String() != "1970-01-01T00:00:00Z - - - - - - - 0b - - 0.000000\n" {
		t.Errorf("invalid stdout output - %s", o2.String())
	}
}
