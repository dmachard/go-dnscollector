package generators

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnscollector/common"
)

func TestStdoutPrint(t *testing.T) {
	// init generator and redirect stdout output to bytes buffer
	var stdout bytes.Buffer
	g := NewStdOut(common.GetFakeConfig(), common.GetFakeLogger(false))
	g.SetBuffer(&stdout)

	// print dns message to stdout buffer
	dm := common.GetFakeDnsMessage()
	g.Print(dm)

	// check buffer
	if stdout.String() != dm.String() {
		t.Errorf("invalid stdout output: %s", stdout.String())
	}
}
