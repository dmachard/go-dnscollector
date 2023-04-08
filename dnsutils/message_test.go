package dnsutils

import (
	"strings"
	"testing"
)

func TestDnsMessage_ToString(t *testing.T) {
	config := GetFakeConfig()

	dm := DnsMessage{}
	dm.Init()

	line := dm.String(strings.Fields(config.Global.TextFormat),
		config.Global.TextFormatDelimiter,
		config.Global.TextFormatBoundary)

	if line != "- - - - - - - - 0b - - -" {
		t.Errorf("text dns message invalid; %s", line)
	}
}

func TestDnsMessage_TextDelimiter(t *testing.T) {
	config := GetFakeConfig()

	dm := DnsMessage{}
	dm.Init()

	line := dm.String(strings.Fields(config.Global.TextFormat),
		";",
		config.Global.TextFormatBoundary)

	if line != "-;-;-;-;-;-;-;-;0b;-;-;-" {
		t.Errorf("text dns message invalid; %s", line)
	}
}

func TestDnsMessage_TextBoundary(t *testing.T) {
	config := GetFakeConfig()

	dm := DnsMessage{}
	dm.Init()

	dm.DNS.Qname = "dns \"collector"

	line := dm.String(strings.Fields(config.Global.TextFormat),
		config.Global.TextFormatDelimiter,
		config.Global.TextFormatBoundary)

	if line != "- - - - - - - - 0b \"dns \\\"collector\" - -" {
		t.Errorf("text dns message invalid; %s", line)
	}
}
