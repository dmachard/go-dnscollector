package generators

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnslogger/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestStdoutPrint(t *testing.T) {
	// init generator and redirect stdout output to bytes buffer
	var stdout bytes.Buffer
	g := NewStdOut(dnsutils.GetFakeConfig(), logger.New(false))
	g.SetBuffer(&stdout)

	// print dns message to stdout buffer
	dm := dnsutils.GetFakeDnsMessage()
	g.Print(dm)

	// check buffer
	if stdout.String() != dm.String() {
		t.Errorf("invalid stdout output: %s", stdout.String())
	}
}
