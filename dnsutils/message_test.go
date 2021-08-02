package dnsutils

import (
	"testing"
)

func TestDnsMessageToText(t *testing.T) {
	dm := DnsMessage{}
	dm.Init()

	line := dm.String()

	if string(line) != "- - - - - - - - 0b - - -\n" {
		t.Errorf("text dns message invalid; %s", line)
	}
}
