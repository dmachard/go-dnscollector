package subprocessors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestDecodePayload_QueryHappy(t *testing.T) {
	payload := []byte{
		//header
		0x9e, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		// name
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Additional records: EDNS OPT with no data, DO = 0, Z=0
		0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x00,
	}

	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err != nil {
		t.Errorf("Unexpected error while decoding payload: %v", err)
	}
	if dm.DNS.MalformedPacket != 0 {
		t.Errorf("did not expect packet to be malformed")
	}

	if dm.DNS.Id != 0x9e84 ||
		dm.DNS.Opcode != 0 ||
		dm.DNS.Rcode != dnsutils.RcodeToString(0) ||
		dm.DNS.Flags.QR ||
		dm.DNS.Flags.TC ||
		dm.DNS.Flags.AA ||
		!dm.DNS.Flags.AD ||
		dm.DNS.Flags.RA {
		t.Error("Invalid DNS header data in message")
	}

	if dm.DNS.Qname != "sensorfleet.com" {
		t.Errorf("Unexpected query name: %s", dm.DNS.Qname)
	}
	if dm.DNS.Qtype != "A" {
		t.Errorf("Unexpected query type: %s", dm.DNS.Qtype)
	}

	if dm.EDNS.Do != 1 ||
		dm.EDNS.UdpSize != 4096 ||
		dm.EDNS.Z != 0 ||
		dm.EDNS.Version != 0 ||
		len(dm.EDNS.Options) != 0 {
		t.Errorf("Unexpected EDNS data")
	}

	if len(dm.DNS.DnsRRs.Answers) != 0 ||
		len(dm.DNS.DnsRRs.Nameservers) != 0 ||
		len(dm.DNS.DnsRRs.Records) != 0 {
		t.Errorf("Unexpected sections parsed")
	}

}
func TestDecodePayload_QueryInvalid(t *testing.T) {
	payload := []byte{
		//header
		0x9e, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		// name
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x83, 0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Additional records: EDNS OPT with no data, DO = 1, Z=0
		0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x00,
	}

	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err == nil {
		t.Errorf("Expected error when parsing payload")
	}
	if dm.DNS.MalformedPacket != 1 {
		t.Errorf("expected packet to be marked as malformed")
	}

	// returned error should wrap the original error
	if !errors.Is(err, dnsutils.ErrDecodeDnsLabelInvalidData) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodePayload_AnswerHappy(t *testing.T) {
	payload := []byte{
		0x9e, 0x84, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x01,
		// Query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Answer 1
		0xc0, 0x0c, // pointer to name
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.1
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x01,
		// Answer 2
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.2
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x02,
		// Answer 3
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.3
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x03,
		// Answer 4
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.4
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x04,
		// Additianl records, EDNS Option, 0 bytes DO=0, Z = 0
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err != nil {
		t.Errorf("Unexpected error while decoding payload: %v", err)
	}
	if dm.DNS.MalformedPacket != 0 {
		t.Errorf("did not expect packet to be malformed")
	}

	if dm.DNS.Id != 0x9e84 ||
		dm.DNS.Opcode != 0 ||
		dm.DNS.Rcode != dnsutils.RcodeToString(0) ||
		!dm.DNS.Flags.QR ||
		dm.DNS.Flags.TC ||
		dm.DNS.Flags.AA ||
		dm.DNS.Flags.AD ||
		!dm.DNS.Flags.RA {
		t.Error("Invalid DNS header data in message")
	}

	if dm.DNS.Qname != "sensorfleet.com" {
		t.Errorf("Unexpected query name: %s", dm.DNS.Qname)
	}
	if dm.DNS.Qtype != "A" {
		t.Errorf("Unexpected query type: %s", dm.DNS.Qtype)
	}

	if len(dm.DNS.DnsRRs.Answers) != 4 {
		t.Errorf("expected 4 answers, got %d", len(dm.DNS.DnsRRs.Answers))
	}

	for i, ans := range dm.DNS.DnsRRs.Answers {
		expected := dnsutils.DnsAnswer{
			Name:      dm.DNS.Qname,
			Rdatatype: dnsutils.RdatatypeToString(0x0001),
			Class:     0x0001,
			Ttl:       300,
			Rdata:     fmt.Sprintf("10.10.1.%d", i+1),
		}
		if expected != ans {
			t.Errorf("unexpected answer (%d). expected %v, got %v", i, expected, ans)
		}
	}

	if dm.EDNS.Do != 0 ||
		dm.EDNS.UdpSize != 1232 ||
		dm.EDNS.Z != 0 ||
		dm.EDNS.Version != 0 ||
		len(dm.EDNS.Options) != 0 {
		t.Errorf("Unexpected EDNS data")
	}

	if len(dm.DNS.DnsRRs.Nameservers) != 0 ||
		len(dm.DNS.DnsRRs.Records) != 0 {
		t.Errorf("Unexpected sections parsed")
	}

}
func TestDecodePayload_AnswerInvalid(t *testing.T) {
	payload := []byte{
		0x9e, 0x84, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x01,
		// Query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Answer 1
		0xc0, 0x0c, // pointer to name
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.1
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x01,
		// Answer 2
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.2
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x02,
		// Answer 3
		0xc0, 0xff,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.3
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x03,
		// Answer 4
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.4
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x04,
		// Additianl records, EDNS Option, 0 bytes DO=0, Z = 0
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err == nil {
		t.Error("expected decoding to fail")
	}
	// returned error should wrap the original error
	if !errors.Is(err, dnsutils.ErrDecodeDnsLabelInvalidPointer) {
		t.Errorf("bad error returned: %v", err)
	}
	if dm.DNS.MalformedPacket != 1 {
		t.Errorf("expected packet to be malformed")
	}
}

func TestDecodePayload_AnswerInvalidQuery(t *testing.T) {
	payload := []byte{
		0x9e, 0x84, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x01,
		// Query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x83, 0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Answer 1
		0xc0, 0x0c, // pointer to name
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.1
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x01,
		// Answer 2
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.2
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x02,
		// Answer 3
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.3
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x03,
		// Answer 4
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.4
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x04,
		// Additianl records, EDNS Option, 0 bytes DO=0, Z = 0
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err == nil {
		t.Error("expected decoding to fail")
	}
	// returned error should wrap the original error
	if !errors.Is(err, dnsutils.ErrDecodeDnsLabelInvalidData) {
		t.Errorf("bad error returned: %v", err)
	}
	if dm.DNS.MalformedPacket != 1 {
		t.Errorf("expected packet to be malformed")
	}

	// after error has been detected in the query part, we should not parse
	// anything from answers
	if len(dm.DNS.DnsRRs.Answers) != 0 {
		t.Errorf("did not expect answers to be parsed, but there were %d parsed", len(dm.DNS.DnsRRs.Answers))
	}
}

func TestDecodePayload_AnswerInvalidEdns(t *testing.T) {
	payload := []byte{
		0x9e, 0x84, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x01,
		// Query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Answer 1
		0xc0, 0x0c, // pointer to name
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.1
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x01,
		// Answer 2
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.2
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x02,
		// Answer 3
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.3
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x03,
		// Answer 4
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.4
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x04,
		// Additianl records, Invalid EDNS Option
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01,
	}

	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err == nil {
		t.Error("expected decoding to fail")
	}
	// returned error should wrap the original error
	if !errors.Is(err, dnsutils.ErrDecodeEdnsOptionTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
	if dm.DNS.MalformedPacket != 1 {
		t.Errorf("expected packet to be malformed")
	}
}

func TestDecodePayload_AnswerInvaliAdditional(t *testing.T) {
	payload := []byte{
		0x9e, 0x84, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x01,
		// Query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Answer 1
		0xc0, 0x0c, // pointer to name
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.1
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x01,
		// Answer 2
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.2
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x02,
		// Answer 3
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.3
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x03,
		// Answer 4
		0xc0, 0x0c,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x01, 0x2c,
		// 10.10.1.4
		0x00, 0x04, 0x0a, 0x0a, 0x01, 0x04,
		// Additianl records, Invalid RDLENGTH
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err == nil {
		t.Error("expected decoding to fail")
	}
	// returned error should wrap the original error
	if !errors.Is(err, dnsutils.ErrDecodeDnsAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
	if dm.DNS.MalformedPacket != 1 {
		t.Errorf("expected packet to be malformed")
	}
}

func TestDecodePayload_AnswerError(t *testing.T) {
	payload := []byte{
		// header
		0xa8, 0x1a, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// query
		0x03, 0x66, 0x6f, 0x6f,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
		0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Authority section
		// name
		0xc0, 0x10,
		// type SOA, class IN
		0x00, 0x06, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x00, 0x3c,
		// RDLENGTH
		0x00, 0x26,
		// RDATA
		// MNAME
		0x03, 0x6e, 0x73, 0x31,
		0xc0, 0x10,
		// RNAME
		0x09, 0x64, 0x6e, 0x73, 0x2d, 0x61,
		0x64, 0x6d, 0x69, 0x6e, 0xc0, 0x10,
		// serial
		0x19, 0xa1, 0x4a, 0xb4,
		// refresh
		0x00, 0x00, 0x03, 0x84,
		// retry
		0x00, 0x00, 0x03, 0x84,
		// expire
		0x00, 0x00, 0x07, 0x08,
		// minimum
		0x00, 0x00, 0x00, 0x3c,
		// Additianl records, EDNS Option, 0 bytes DO=1, Z = 0
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00,
		0x00, 0x80, 0x00, 0x00, 0x00,
	}
	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err != nil {
		t.Errorf("Unexpected error while decoding payload: %v", err)
	}
	if dm.DNS.MalformedPacket != 0 {
		t.Errorf("did not expect packet to be malformed")
	}

	if dm.DNS.Id != 0xa81a ||
		dm.DNS.Opcode != 0 ||
		dm.DNS.Rcode != dnsutils.RcodeToString(3) ||
		!dm.DNS.Flags.QR ||
		dm.DNS.Flags.TC ||
		dm.DNS.Flags.AA ||
		dm.DNS.Flags.AD ||
		!dm.DNS.Flags.RA {
		t.Error("Invalid DNS header data in message")
	}

	if dm.DNS.Qname != "foo.google.com" {
		t.Errorf("Unexpected query name: %s", dm.DNS.Qname)
	}
	if dm.DNS.Qtype != "A" {
		t.Errorf("Unexpected query type: %s", dm.DNS.Qtype)
	}

	if len(dm.DNS.DnsRRs.Answers) != 0 {
		t.Errorf("did not expect any answers, got %d", len(dm.DNS.DnsRRs.Answers))
	}

	if len(dm.DNS.DnsRRs.Nameservers) != 1 {
		t.Errorf("expected 1 authority RR, got %d", len(dm.DNS.DnsRRs.Nameservers))
	}
	expected := dnsutils.DnsAnswer{
		Name:      "google.com",
		Rdatatype: dnsutils.RdatatypeToString(0x0006),
		Class:     0x0001,
		Ttl:       60,
		Rdata:     "ns1.google.com dns-admin.google.com 430000820 900 900 1800 60",
	}

	if dm.DNS.DnsRRs.Nameservers[0] != expected {
		t.Errorf("unexpected SOA record parsed, expected %v, git %v", expected, dm.DNS.DnsRRs.Nameservers[0])
	}

	if dm.EDNS.Do != 1 ||
		dm.EDNS.UdpSize != 1232 ||
		dm.EDNS.Z != 0 ||
		dm.EDNS.Version != 0 ||
		len(dm.EDNS.Options) != 0 {
		t.Errorf("Unexpected EDNS data")
	}

}

func TestDecodePayload_AnswerError_Invalid(t *testing.T) {
	payload := []byte{
		// header
		0xa8, 0x1a, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// query
		0x03, 0x66, 0x6f, 0x6f,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
		0x63, 0x6f, 0x6d, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// Authority section
		// name
		0xc0, 0x10,
		// type SOA, class IN
		0x00, 0x06, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x00, 0x3c,
		// RDLENGTH
		0x00, 0x26,
		// RDATA
		// MNAME, invalid offset in pointer
		0x03, 0x6e, 0x73, 0x31,
		0xc0, 0xff,
		// RNAME
		0x09, 0x64, 0x6e, 0x73, 0x2d, 0x61,
		0x64, 0x6d, 0x69, 0x6e, 0xc0, 0x10,
		// serial
		0x19, 0xa1, 0x4a, 0xb4,
		// refresh
		0x00, 0x00, 0x03, 0x84,
		// retry
		0x00, 0x00, 0x03, 0x84,
		// expire
		0x00, 0x00, 0x07, 0x08,
		// minimum
		0x00, 0x00, 0x00, 0x3c,
		// Additianl records, EDNS Option, 0 bytes DO=1, Z = 0
		0x00, 0x00, 0x29, 0x04, 0xd0, 0x00,
		0x00, 0x80, 0x00, 0x00, 0x00,
	}
	dm := dnsutils.DnsMessage{}
	dm.DNS.Payload = payload
	dm.DNS.Length = len(payload)

	header, err := dnsutils.DecodeDns(payload)
	if err != nil {
		t.Errorf("unexpected error when decoding header: %v", err)
	}

	if err = decodePayload(&dm, &header, false, dnsutils.GetFakeConfig()); err == nil {
		t.Error("expected decoding to fail")
	}
	// returned error should wrap the original error
	if !errors.Is(err, dnsutils.ErrDecodeDnsLabelInvalidPointer) {
		t.Errorf("bad error returned: %v", err)
	}
	if dm.DNS.MalformedPacket != 1 {
		t.Errorf("expected packet to be malformed")
	}

}
