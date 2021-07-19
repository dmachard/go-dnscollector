package dnsmessage

import (
	"testing"
)

func TestDnsMessageToText(t *testing.T) {
	dm := DnsMessage{}
	dm.Init()

	line := TransformToText(dm)

	if string(line) != "1970-01-01T00:00:00Z - - - - - - - 0b - - 0.000000\n" {
		t.Errorf("text dns message invalid")
	}
}
