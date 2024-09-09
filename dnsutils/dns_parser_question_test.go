package dnsutils

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestDecodeQuestion(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)
	payload, _ := dm.Pack()

	qname, qtype, qclass, offsetRR, _ := DecodeQuestion(1, payload)
	if ClassToString(qclass) != "IN" {
		t.Errorf("invalid qclass: %d", qclass)
	}

	if qname+"." != fqdn {
		t.Errorf("invalid qname: %s", qname)
	}

	if RdatatypeToString(qtype) != "A" {
		t.Errorf("invalid qtype: %d", qtype)
	}
	if offsetRR != len(payload) {
		t.Errorf("invalid offset: %d, payload len: %d", offsetRR, len(payload))
	}
}

func TestDecodeQuestion_Multiple(t *testing.T) {
	paylaod := []byte{
		0x9e, 0x84, 0x01, 0x20, 0x00, 0x03, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// query 1
		0x01, 0x61, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// query 2
		0x01, 0x62, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// query 3
		0x01, 0x63, 0x00,
		// type AAAA, class IN
		0x00, 0x1c, 0x00, 0x01,
	}

	qname, qtype, qclass, offset, err := DecodeQuestion(3, paylaod)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	if qname != "c" || RdatatypeToString(qtype) != "AAAA" {
		t.Errorf("expected qname=C, type=AAAA, got qname=%s, type=%s", qname, RdatatypeToString(qtype))
	}
	if ClassToString(qclass) != "IN" {
		t.Errorf("expected qclass=IN %s", ClassToString(qclass))
	}
	if offset != 33 {
		t.Errorf("expected resulting offset to be 33, got %d", offset)
	}
}

func TestDecodeQuestion_Multiple_InvalidCount(t *testing.T) {
	paylaod := []byte{
		0x9e, 0x84, 0x01, 0x20, 0x00, 0x04, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// query 1
		0x01, 0x61, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// query 2
		0x01, 0x62, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// query 3
		0x01, 0x63, 0x00,
		// type AAAA, class IN
		0x00, 0x1c, 0x00, 0x01,
	}

	_, _, _, _, err := DecodeQuestion(4, paylaod)
	if !errors.Is(err, ErrDecodeDNSLabelTooShort) {
		t.Errorf("bad error received: %v", err)
	}
}

func TestDecodeQuestion_SkipOpt(t *testing.T) {
	payload := []byte{
		0x43, 0xac, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00,
		// Query section
		0x0f, 0x64, 0x6e, 0x73,
		0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
		0x63, 0x74, 0x6f, 0x72, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Answer Resource Records
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type OPT, class IN
		0x00, 0x29, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x01,
		// RDATA
		0x01,
		// 2nd resource record
		0x0f, 0x64,
		0x6e, 0x73, 0x74, 0x61, 0x70, 0x63, 0x6f, 0x6c,
		0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x04, 0x74,
		0x65, 0x73, 0x74, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x04,
		// RDATA
		0x7f, 0x00, 0x00, 0x01,
	}
	_, _, _, offsetrr, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("Unexpected error decoding question: %v", err)
	}

	answer, _, erra := DecodeAnswer(2, offsetrr, payload)
	if erra != nil {
		t.Errorf("Unexpected error decoding answer: %v", erra)
	}
	if len(answer) != 1 {
		t.Fatalf("Expected answer to contain one resource record, got %d", len(answer))
	}
	if answer[0].Rdatatype != RdatatypeToString(0x01) || answer[0].Rdata != "127.0.0.1" {
		t.Errorf("unexpected answer %s %s, expected A 127.0.0.1", answer[0].Rdatatype, answer[0].Rdata)
	}
}

func TestDecodeDnsQuestion_InvalidOffset(t *testing.T) {
	decoded := []byte{183, 59, 130, 217, 128, 16, 0, 51, 165, 67, 0, 0}
	_, _, _, _, err := DecodeQuestion(1, decoded)
	if !errors.Is(err, ErrDecodeDNSLabelTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsQuestion_PacketTooShort(t *testing.T) {
	decoded := []byte{183, 59, 130, 217, 128, 16, 0, 51, 165, 67, 0, 0, 1, 1, 8, 10, 23}
	_, _, _, _, err := DecodeQuestion(1, decoded)
	if !errors.Is(err, ErrDecodeDNSLabelTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsQuestion_QtypeMissing(t *testing.T) {
	decoded := []byte{88, 27, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112,
		99, 111, 108, 108, 101, 99, 116, 111, 114, 4, 116, 101, 115, 116, 0}
	_, _, _, _, err := DecodeQuestion(1, decoded)
	if !errors.Is(err, ErrDecodeQuestionQtypeTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsQuestion_InvalidPointer(t *testing.T) {
	decoded := []byte{88, 27, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 202}
	_, _, _, _, err := DecodeQuestion(1, decoded)
	if !errors.Is(err, ErrDecodeDNSLabelTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}
