package dnsutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

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

func TestDecodeRdataA(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "127.0.0.1"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s A %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata A, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataA_Short(t *testing.T) {
	payload := []byte{
		0x43, 0xac, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// Query section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Answer Resource Record
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x03,
		// RDATA (1 byte too short for A record)
		0x7f, 0x00, 0x00,
	}
	_, _, _, offsetrr, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("Unexpected error decoding question: %v", err)
	}

	_, _, erra := DecodeAnswer(1, offsetrr, payload)
	if !errors.Is(erra, ErrDecodeDNSAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", erra)
	}
}

func TestDecodeRdataAAAA(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "fe8::2"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s AAAA %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata AAAA, want %s, got: %s", rdata, answer[0].Rdata)
	}
}
func TestDecodeRdataAAAA_Short(t *testing.T) {
	payload := []byte{
		// header
		0x3b, 0x33, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// Query section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Answer resource record
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type AAAA, class IN
		0x00, 0x1c, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x0c,
		// RDATA
		0xfe, 0x80,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	}

	_, _, _, offsetSetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}
	_, _, erra := DecodeAnswer(1, offsetSetRR, payload)
	if !errors.Is(erra, ErrDecodeDNSAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", erra)
	}
}

func TestDecodeRdataCNAME(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "test.collector.org"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s CNAME %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata CNAME, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataMX(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "5 gmail-smtp-in.l.google.com"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s MX %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata MX, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataMX_Short(t *testing.T) {
	payload := []byte{
		// header
		0xed, 0x7f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// Question seection
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Answer Resource Record
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type MX, class IN
		0x00, 0x0f, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x01,
		// RDATA
		0x00,
	}
	_, _, _, offsetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}
	_, _, erra := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(erra, ErrDecodeDNSAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", erra)
	}

}

func TestDecodeRdataMX_Minimal(t *testing.T) {
	payload := []byte{
		// header
		0xed, 0x7f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// Question seection
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Answer Resource Record
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type MX, class IN
		0x00, 0x0f, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x03,
		// RDATA
		0x00, 0x00, 0x00,
	}
	_, _, _, offsetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}
	answer, _, erra := DecodeAnswer(1, offsetRR, payload)
	if erra != nil {
		t.Errorf("unexpected error while decoding answer: %v", err)
	}
	expected := "0 "
	if answer[0].Rdata != expected {
		t.Errorf("invalid decode for MX rdata, expected %s got %s", expected, answer[0].Rdata)
	}
}

func TestDecodeRdataSRV(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "20 0 5222 alt2.xmpp.l.google.com"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s SRV %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata SRV, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataSRV_Short(t *testing.T) {
	payload := []byte{
		// header
		0xd9, 0x93, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// Question section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Answer section
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type SRV, class IN
		0x00, 0x21, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x04,
		// RDATA
		// priority
		0x00, 0x14,
		// weight
		0x00, 0x00,
		// missing port and target
	}

	_, _, _, offsetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}
	_, _, erra := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(erra, ErrDecodeDNSAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", erra)
	}
}

func TestDecodeRdataSRV_Minimal(t *testing.T) {
	payload := []byte{
		// header
		0xd9, 0x93, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// Question section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Answer section
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type SRV, class IN
		0x00, 0x21, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x07,
		// RDATA
		// priority
		0x00, 0x14,
		// weight
		0x00, 0x00,
		// port
		0x00, 0x10,
		// empty target
		0x00,
	}

	_, _, _, offsetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}
	answer, _, erra := DecodeAnswer(1, offsetRR, payload)
	if erra != nil {
		t.Errorf("unexpected error while decoding answer: %v", err)
	}
	expectedRdata := "20 0 16 "
	if answer[0].Rdata != expectedRdata {
		t.Errorf("invalid decode for rdata SRV, want %s, got: %s", expectedRdata, answer[0].Rdata)
	}
}
func TestDecodeRdataNS(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "ns1.dnscollector"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s NS %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata NS, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataTXT(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "hello world"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s TXT \"%s\"", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata TXT, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataTXT_Empty(t *testing.T) {
	payload := []byte{
		// header
		0x86, 0x08, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// question section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// answer section
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type TXT, class IN
		0x00, 0x10, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x00,
		// no data
	}

	_, _, _, offsetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}
	_, _, erra := DecodeAnswer(1, offsetRR, payload)
	if erra != nil {
		t.Error("expected no error on decode", erra)
	}

}
func TestDecodeRdataTXT_Short(t *testing.T) {
	payload := []byte{
		// header
		0x86, 0x08, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// question section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// answer section
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type TXT, class IN
		0x00, 0x10, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x0a,
		//  RDATA
		// length
		0x0b,
		// characters
		0x68,
		0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72,
		// missing two bytes
	}

	_, _, _, offsetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}
	_, _, erra := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(erra, ErrDecodeDNSAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", erra)
	}

}
func TestDecodeRdataTXT_NoTxt(t *testing.T) {
	payload := []byte{
		// header
		0x86, 0x08, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// question section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// answer section
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type TXT, class IN
		0x00, 0x10, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x01,
		//  RDATA
		// length
		0x00,
		// no txt-data
	}

	_, _, _, offsetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}
	answer, _, erra := DecodeAnswer(1, offsetRR, payload)
	if erra != nil {
		t.Errorf("unexpected error while decoding answer: %v", err)
	}

	if answer[0].Rdata != "" {
		t.Errorf("expected empty string in RDATA, got: %s", answer[0].Rdata)
	}

}

func TestDecodeRdataPTR(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "one.one.one.one"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s PTR %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata PTR, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataSOA(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rdata := "ns1.google.com dns-admin.google.com 412412655 900 900 1800 60"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s SOA %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata SOA, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataSOA_Short(t *testing.T) {
	payload := []byte{
		// header
		0x28, 0xba, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		// Query section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Answer Resource Record,
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type SOA, class IN
		0x00, 0x06, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH 54
		0x00, 0x36,
		// RDATA
		// MNAME
		0x03, 0x6e,
		0x73, 0x31, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
		0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		// RNAME
		0x09, 0x64,
		0x6e, 0x73, 0x2d, 0x61, 0x64, 0x6d, 0x69, 0x6e,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
		0x63, 0x6f, 0x6d, 0x00,
		// serial
		0x18, 0x94, 0xea, 0xef,
		// refresh
		0x00, 0x00, 0x03, 0x84,
		// retry
		0x00, 0x00, 0x03, 0x84,
		// expire
		0x00, 0x00, 0x07, 0x08,
		// minimum -field missing from the RDATA
	}

	_, _, _, offsetRR, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("Unable to decode question: %v", err)
	}
	_, _, erra := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(erra, ErrDecodeDNSAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", erra)
	}
}

func TestDecodeRdataSOA_Minimization(t *testing.T) {
	// loop between qnames
	payload := []byte{164, 66, 129, 128, 0, 1, 0, 0, 0, 1, 0, 0, 8, 102, 114, 101, 115, 104, 114, 115, 115, 4, 109,
		99, 104, 100, 2, 109, 101, 0, 0, 28, 0, 1, 192, 21, 0, 6, 0, 1, 0, 0, 0, 60, 0, 43, 6, 100, 110, 115, 49, 48,
		51, 3, 111, 118, 104, 3, 110, 101, 116, 0, 4, 116, 101, 99, 104, 192, 53,
		120, 119, 219, 34, 0, 1, 81, 128, 0, 0, 14, 16, 0, 54, 238, 128, 0, 0, 0, 60}

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, _, err := DecodeAnswer(1, offsetRR, payload)
	if err != nil {
		t.Errorf(" error returned: %v", err)
	}
}

func TestDecodeRdataSVCB_alias(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeSVCB)

	// draft-ietf-dnsop-svcb-https-12 Appendix D.1
	rdata := "0 foo.example.com"
	rr1, _ := dns.NewRR(fmt.Sprintf("%s SVCB %s", fqdn, rdata))
	dm.Answer = append(dm.Answer, rr1)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	if answer[0].Rdata != rdata {
		t.Errorf("invalid decode for rdata SOA, want %s, got: %s", rdata, answer[0].Rdata)
	}
}

func TestDecodeRdataSVCB_params(t *testing.T) {
	fqdn := TestQName

	vectors := []string{
		"0 foo.example.com",                       // draft-ietf-dnsop-svcb-https-12 Appendix D.1
		"1 .",                                     // draft-ietf-dnsop-svcb-https-12 Appendix D.2, figure 3
		"16 foo.example.com port=53",              // draft-ietf-dnsop-svcb-https-12 Appendix D.2, figure 4
		"1 foo.example.com key667=hello",          // draft-ietf-dnsop-svcb-https-12 Appendix D.2, figure 5
		`1 foo.example.com key667="hello\210qoo"`, // draft-ietf-dnsop-svcb-https-12 Appendix D.2, figure 6
		"1 foo.example.com ipv6hint=2001:db8::1,2001:db8::53:1",                       // draft-ietf-dnsop-svcb-https-12 Appendix D.2, figure 7, modified (single line)
		"16 foo.example.org mandatory=alpn,ipv4hint alpn=h2,h3-19 ipv4hint=192.0.2.1", // draft-ietf-dnsop-svcb-https-12 Appendix D.2, figure 9, modified (sorted)
		"16 foo.example.org mandatory=alpn,ipv4hint alpn=h2,h3-19 ipv4hint=192.0.2.1,192.0.2.2",
	}

	for _, rdata := range vectors {
		dm := new(dns.Msg)
		dm.SetQuestion(fqdn, dns.TypeSVCB)
		rr1, _ := dns.NewRR(fmt.Sprintf("%s SVCB %s", fqdn, rdata))
		dm.Answer = append(dm.Answer, rr1)
		payload, _ := dm.Pack()
		_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
		answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)
		if answer[0].Rdata != rdata {
			t.Errorf("invalid decode for rdata SVCB, want %s, got: %s", rdata, answer[0].Rdata)
		}
	}
}
