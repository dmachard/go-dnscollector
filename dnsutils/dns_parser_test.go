package dnsutils

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestRcodeValid(t *testing.T) {
	rcode := RcodeToString(0)
	if rcode != "NOERROR" {
		t.Errorf("rcode noerror expected: %s", rcode)
	}
}

func TestRcodeInvalid(t *testing.T) {
	rcode := RcodeToString(100000)
	if rcode != "UNKNOWN" {
		t.Errorf("invalid rcode - expected: %s", rcode)
	}
}

func TestDecodeDns(t *testing.T) {
	dm := new(dns.Msg)
	dm.SetQuestion(TestQName, dns.TypeA)

	payload, _ := dm.Pack()
	_, err := DecodeDNS(payload)
	if err != nil {
		t.Errorf("decode dns error: %s", err)
	}
}

func TestDecodeDns_HeaderTooShort(t *testing.T) {
	decoded := []byte{183, 59}
	_, err := DecodeDNS(decoded)
	if !errors.Is(err, ErrDecodeDNSHeaderTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}
