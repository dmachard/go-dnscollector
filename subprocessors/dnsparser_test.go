package subprocessors

import (
	"errors"
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

func TestDecodeRdataA(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "127.0.0.1"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s A %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata A, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataAAAA(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "fe80:0:0:0:0:0:0:2"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s AAAA %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata AAAA, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataCNAME(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "test.collector.org"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s CNAME %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata CNAME, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataMX(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "5 gmail-smtp-in.l.google.com"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s MX %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata MX, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataSRV(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "20 0 5222 alt2.xmpp.l.google.com"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s SRV %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata SRV, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataNS(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "ns1.dnscollector"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s NS %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata NS, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataTXT(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "hello world"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s TXT \"%s\"", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata TXT, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataPTR(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "one.one.one.one"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s PTR %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata PTR, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataSOA(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "ns1.google.com dns-admin.google.com 412412655 900 900 1800 60"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s SOA %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	answer, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata SOA, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeDns_HeaderTooShort(t *testing.T) {
	decoded := []byte{183, 59}
	_, _, _, _, _, err := DecodeDns(decoded)
	if !errors.Is(err, ErrDecodeDnsHeaderTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsQuestion_InvalidOffset(t *testing.T) {
	decoded := []byte{183, 59, 130, 217, 128, 16, 0, 51, 165, 67, 0, 0}
	_, _, _, err := DecodeQuestion(decoded)
	if !errors.Is(err, ErrDecodeDnsLabelInvalidOffset) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsQuestion_PacketTooShort(t *testing.T) {
	decoded := []byte{183, 59, 130, 217, 128, 16, 0, 51, 165, 67, 0, 0, 1, 1, 8, 10, 23}
	_, _, _, err := DecodeQuestion(decoded)
	if !errors.Is(err, ErrDecodeDnsLabelTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsQuestion_QtypeMissing(t *testing.T) {
	decoded := []byte{88, 27, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112,
		99, 111, 108, 108, 101, 99, 116, 111, 114, 4, 116, 101, 115, 116, 0}
	_, _, _, err := DecodeQuestion(decoded)
	if !errors.Is(err, ErrDecodeQuestionQtypeTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_PacketTooShort(t *testing.T) {
	payload := []byte{46, 172, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0}

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, err := DecodeAnswer(1, offset_rr, payload)
	if !errors.Is(err, ErrDecodeDnsAnswerTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_RdataTooShort(t *testing.T) {
	payload := []byte{46, 172, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 127, 0}

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, err := DecodeAnswer(1, offset_rr, payload)
	if !errors.Is(err, ErrDecodeDnsAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}
