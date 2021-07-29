package dnsmessage

import (
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
	if rcode != "-" {
		t.Errorf("invalid rcode - expected: %s", rcode)
	}
}

func TestRdatatypeValid(t *testing.T) {
	rdt := RdatatypeToString(1)
	if rdt != "A" {
		t.Errorf("rdatatype A expected: %s", rdt)
	}
}

func TestRdatatypeInvalid(t *testing.T) {
	rdt := RdatatypeToString(100000)
	if rdt != "-" {
		t.Errorf("rdatatype - expected: %s", rdt)
	}
}

func TestDecodeDns(t *testing.T) {
	dm := new(dns.Msg)
	dm.SetQuestion("dnstapcollector.test.", dns.TypeA)

	payload, _ := dm.Pack()
	_, _, _, _, err := DecodeDns(payload)
	if err != nil {
		t.Errorf("decode dns error: %s", err)
	}
}

func TestDecodeDnsInvalid(t *testing.T) {
	dm := new(dns.Msg)
	dm.SetQuestion("dnstapcollector.test.", dns.TypeA)

	payload, _ := dm.Pack()
	_, _, _, _, err := DecodeDns(payload[:4])
	if err == nil {
		t.Errorf("invalid packet dns error expected")
	}
}

func TestDecodeQuestion(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)
	payload, _ := dm.Pack()

	qname, qtype, offset_rr := DecodeQuestion(payload)
	if qname+"." != fqdn {
		t.Errorf("invalid qname: %s", qname)
	}

	if RdatatypeToString(qtype) != "A" {
		t.Errorf("invalid qtype: %d", qtype)
	}
	if offset_rr != len(payload) {
		t.Errorf("invalid offset: %d, payload len: %d", offset_rr, len(payload))
	}
}
