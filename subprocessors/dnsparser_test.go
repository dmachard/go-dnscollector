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
	if rcode != "UNKNOWN" {
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
	if rdt != "UNKNOWN" {
		t.Errorf("rdatatype - expected: %s", rdt)
	}
}

func TestDecodeDns(t *testing.T) {
	dm := new(dns.Msg)
	dm.SetQuestion("dnstapcollector.test.", dns.TypeA)

	payload, _ := dm.Pack()
	_, err := DecodeDns(payload)
	if err != nil {
		t.Errorf("decode dns error: %s", err)
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

func TestDecodeAnswer_Ns(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rrNs, _ := dns.NewRR("root-servers.net NS c.root-servers.net")
	rrA, _ := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", fqdn))

	m := new(dns.Msg)
	m.SetReply(dm)
	m.Authoritative = true
	m.Answer = append(m.Answer, rrA)
	m.Ns = append(m.Ns, rrNs)

	payload, _ := m.Pack()
	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, offset_rrns, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	nsAnswers, _, _ := DecodeAnswer(len(m.Ns), offset_rrns, payload)
	if len(nsAnswers) != len(m.Ns) {
		t.Errorf("invalid decode answer, want %d, got: %d", len(m.Ns), len(nsAnswers))
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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if len(answer) != len(dm.Answer) {
		t.Errorf("invalid decode answer, want %d, got: %d", len(dm.Answer), len(answer))
	}
}

func TestDecodeAnswer_QnameMinimized(t *testing.T) {
	payload := []byte{0x8d, 0xda, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x05, 0x74,
		0x65, 0x61, 0x6d, 0x73, 0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00,
		0x01, 0x00, 0x00, 0x50, 0xa8, 0x00, 0x0f, 0x05, 0x74, 0x65, 0x61, 0x6d, 0x73, 0x06,
		0x6f, 0x66, 0x66, 0x69, 0x63, 0x65, 0xc0, 0x1c, 0xc0, 0x31, 0x00, 0x05, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3e, 0x00, 0x26, 0x10, 0x74, 0x65, 0x61, 0x6d, 0x73, 0x2d, 0x6f, 0x66,
		0x66, 0x69, 0x63, 0x65, 0x2d, 0x63, 0x6f, 0x6d, 0x06, 0x73, 0x2d, 0x30, 0x30, 0x30, 0x35,
		0x08, 0x73, 0x2d, 0x6d, 0x73, 0x65, 0x64, 0x67, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0,
		0x4c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7a, 0x00, 0x13, 0x06, 0x73, 0x2d, 0x30,
		0x30, 0x30, 0x35, 0x09, 0x64, 0x63, 0x2d, 0x6d, 0x73, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x6d,
		0xc0, 0x7e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x04, 0x34, 0x71, 0xc3,
		0x84, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, _, err := DecodeAnswer(4, offset_rr, payload)
	if err != nil {
		t.Errorf("failed to decode valid dns packet with minimization")
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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

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
	answer, _, _ := DecodeAnswer(len(dm.Answer), offset_rr, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata SOA, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeDns_HeaderTooShort(t *testing.T) {
	decoded := []byte{183, 59}
	_, err := DecodeDns(decoded)
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
	_, _, err := DecodeAnswer(1, offset_rr, payload)
	if !errors.Is(err, ErrDecodeDnsAnswerTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_RdataTooShort(t *testing.T) {
	payload := []byte{46, 172, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 127, 0}

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, _, err := DecodeAnswer(1, offset_rr, payload)
	if !errors.Is(err, ErrDecodeDnsAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_InvalidPtr(t *testing.T) {
	payload := []byte{128, 177, 129, 160, 0, 1, 0, 1, 0, 0, 0, 1, 5, 104, 101, 108, 108, 111, 4,
		109, 99, 104, 100, 2, 109, 101, 0, 0, 1, 0, 1, 192, 254, 0, 1, 0, 1, 0, 0,
		14, 16, 0, 4, 83, 112, 146, 176}

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, _, err := DecodeAnswer(1, offset_rr, payload)
	if !errors.Is(err, ErrDecodeDnsLabelInvalidOffset) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_InvalidPtr_Loop1(t *testing.T) {
	// loop qname on himself
	payload := []byte{128, 177, 129, 160, 0, 1, 0, 1, 0, 0, 0, 1, 5, 104, 101, 108, 108, 111, 4,
		109, 99, 104, 100, 2, 109, 101, 0, 0, 1, 0, 1, 192, 31, 0, 1, 0, 1, 0, 0,
		14, 16, 0, 4, 83, 112, 146, 176}

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, _, err := DecodeAnswer(1, offset_rr, payload)
	if !errors.Is(err, ErrDecodeDnsLabelInvalidOffsetInfiniteLoop) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_InvalidPtr_Loop2(t *testing.T) {
	// loop between qnames
	payload := []byte{128, 177, 129, 160, 0, 1, 0, 2, 0, 0, 0, 1, 5, 104, 101, 108, 108, 111, 4,
		109, 99, 104, 100, 2, 109, 101, 0, 0, 1, 0, 1, 192, 47, 0, 1, 0, 1, 0, 0,
		14, 16, 0, 4, 83, 112, 146, 176, 192, 31, 0, 1, 0, 1, 0, 0,
		14, 16, 0, 4, 83, 112, 146, 176}

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, _, err := DecodeAnswer(1, offset_rr, payload)
	if !errors.Is(err, ErrDecodeDnsLabelInvalidOffsetInfiniteLoop) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeQuery_EDNS(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	e := &dns.OPT{}
	e.Hdr.Name = "."
	e.Hdr.Rrtype = dns.TypeOPT
	e.SetUDPSize(1024)
	e.SetDo()
	e.SetVersion(2)
	e.SetZ(23)
	fmt.Println(e)

	dm.Extra = append(dm.Extra, e)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, _, err := DecodeEDNS(len(dm.Extra), offset_rr, payload)

	if err != nil {
		t.Errorf("edns error returned: %v", err)
	}
}

func TestDecodeReply_EDNS(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rrA, _ := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", fqdn))

	m := new(dns.Msg)
	m.SetReply(dm)
	m.Answer = append(m.Answer, rrA)

	e := &dns.OPT{}
	e.Hdr.Name = "."
	e.Hdr.Rrtype = dns.TypeOPT
	e.SetUDPSize(1024)
	e.SetDo()
	e.SetVersion(2)
	e.SetZ(23)

	m.Extra = append(dm.Extra, e)

	m.SetRcode(dm, 42) // 32(extended rcode) + 10(rcode)

	payload, _ := m.Pack()
	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, offset_rr, _ = DecodeAnswer(len(m.Answer), offset_rr, payload)

	_, _, err := DecodeEDNS(len(m.Extra), offset_rr, payload)
	fmt.Println(err)
}
