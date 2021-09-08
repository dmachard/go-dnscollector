package loggers

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestStdoutPrint(t *testing.T) {
	// init logger and redirect stdout output to bytes buffer
	var stdout bytes.Buffer
	g := NewStdOut(dnsutils.GetFakeConfig(), logger.New(false))
	g.SetBuffer(&stdout)

	// print dns message to stdout buffer
	dm := dnsutils.GetFakeDnsMessage()
	g.stdout.Print(dm.String(g.textFormat))

	// check buffer
	if stdout.String() != dm.String(g.textFormat) {
		t.Errorf("invalid stdout output: %s", stdout.String())
	}
}
