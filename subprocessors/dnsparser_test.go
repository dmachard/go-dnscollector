package subprocessors

import (
	"fmt"
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
	_, _, _, _, _, err := DecodeDns(payload)
	if err != nil {
		t.Errorf("decode dns error: %s", err)
	}
}

func TestDecodeDnsInvalid(t *testing.T) {
	dm := new(dns.Msg)
	dm.SetQuestion("dnstapcollector.test.", dns.TypeA)

	payload, _ := dm.Pack()
	_, _, _, _, _, err := DecodeDns(payload[:4])
	if err == nil {
		t.Errorf("invalid packet dns error expected")
	}
}

func TestDecodeQuestion(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)
	payload, _ := dm.Pack()

	qname, qtype, offset_rr, _ := DecodeQuestion(payload)
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

func TestDecodeAnswer(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)
	rr1, _ := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", fqdn))
	rr2, _ := dns.NewRR(fmt.Sprintf("%s A 127.0.0.2", fqdn))
	dm.Answer = append(dm.Answer, rr1)
	dm.Answer = append(dm.Answer, rr2)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if len(answer) != len(dm.Answer) {
		t.Errorf("invalid decode answer, want %d, got: %d", len(dm.Answer), len(answer))
	}
}

func TestDecodeInvalidHeader(t *testing.T) {
	decoded := []byte{183, 59}
	_, _, _, _, _, err := DecodeDns(decoded)
	if err == nil {
		t.Errorf("invalid decode header")
	}
}

func TestDecodeInvalidQuestion(t *testing.T) {
	decoded := []byte{183, 59, 130, 217, 128, 16, 0, 51, 165, 67, 0, 0, 1, 1, 8, 10, 23}
	_, _, _, err := DecodeQuestion(decoded)
	if err == nil {
		t.Errorf("invalid decode question")
	}
}
