package dnsutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

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

	dm.Extra = append(dm.Extra, e)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(1, payload)
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

	o := &dns.EDNS0_COOKIE{Code: 10, Cookie: "aaaa"}
	e.Option = append(e.Option, o)

	m.Extra = append(dm.Extra, e)

	m.SetRcode(dm, 42) // 32(extended rcode) + 10(rcode)

	payload, _ := m.Pack()
	_, _, offset_rr, _ := DecodeQuestion(1, payload)
	_, offset_rr, _ = DecodeAnswer(len(m.Answer), offset_rr, payload)

	_, _, err := DecodeEDNS(len(m.Extra), offset_rr, payload)
	if err != nil {
		t.Errorf("edns error returned: %v", err)
	}
}

func TestDecodeQuery_EdnsSubnet(t *testing.T) {
	payload := []byte{
		// header
		0xe9, 0x9d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Additional records section
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x0b,
		//RDATA
		// CODE - Client subnet
		0x00, 0x08,
		// Length
		0x00, 0x07,
		// Option data
		// family
		0x00, 0x01,
		// prefix-len
		0x18,
		// scope prefix-len
		0x00,
		// address
		0xc0, 0xa8, 0x01,
	}

	_, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	answer, _, erra := DecodeAnswer(1, offset, payload)
	if erra != nil {
		t.Errorf("unexpected error while decoding answer: %v", erra)
	}
	// parsing answers should skip the OPT type and not return anything from
	// the additional section
	if len(answer) > 0 {
		t.Errorf("did not expect any answers to be parsed, got %d", len(answer))
	}
	edns, _, erre := DecodeEDNS(1, offset, payload)
	if erre != nil {
		t.Errorf("unexpected error when decoding EDNS: %v", erre)
	}
	if edns.Do != 1 || edns.Z != 0 || edns.Version != 0 || edns.UdpSize != 1232 || edns.ExtendedRcode != 0 {
		t.Errorf("invalid data in parsed EDNS header: %v", edns)
	}

	if len(edns.Options) != 1 {
		t.Errorf("expected 1 EDNS option to be parsed, got %v", len(edns.Options))
	}

	expected_option := DnsOption{Code: 0x0008, Name: OptCodeToString(0x0008), Data: "192.168.1.0/24"}

	if edns.Options[0] != expected_option {
		t.Errorf("bad option parsed, expected %v, got %v", expected_option, edns.Options[0])
	}

}
func TestDecodeQuery_EdnsSubnetV6(t *testing.T) {
	payload := []byte{
		// header
		0xe9, 0x9d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Additional records section
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x0b,
		//RDATA
		// CODE - Client subnet
		0x00, 0x08,
		// Length
		0x00, 0x07,
		// Option data
		// family
		0x00, 0x02,
		// prefix-len
		0x18,
		// scope prefix-len
		0x00,
		// address
		0xfe, 0x80, 0x01,
	}

	_, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	answer, _, erra := DecodeAnswer(1, offset, payload)
	if erra != nil {
		t.Errorf("unexpected error while decoding answer: %v", erra)
	}
	// parsing answers should skip the OPT type and not return anything from
	// the additional section
	if len(answer) > 0 {
		t.Errorf("did not expect any answers to be parsed, got %d", len(answer))
	}
	edns, _, erre := DecodeEDNS(1, offset, payload)
	if erre != nil {
		t.Errorf("unexpected error when decoding EDNS: %v", erre)
	}
	if edns.Do != 1 || edns.Z != 0 || edns.Version != 0 || edns.UdpSize != 1232 || edns.ExtendedRcode != 0 {
		t.Errorf("invalid data in parsed EDNS header: %v", edns)
	}

	if len(edns.Options) != 1 {
		t.Errorf("expected 1 EDNS option to be parsed, got %v", len(edns.Options))
	}

	expected_option := DnsOption{Code: 0x0008, Name: OptCodeToString(0x0008), Data: "[fe80:100::]/24"}

	if edns.Options[0] != expected_option {
		t.Errorf("bad option parsed, expected %v, got %v", expected_option, edns.Options[0])
	}

}

func TestDecodeQuery_EdnsSubnet_invalidFam(t *testing.T) {
	payload := []byte{
		// header
		0xe9, 0x9d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Additional records section
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x0b,
		//RDATA
		// CODE - Client subnet
		0x00, 0x08,
		// Length
		0x00, 0x07,
		// Option data
		// family
		0x00, 0xff,
		// prefix-len
		0x18,
		// scope prefix-len
		0x00,
		// address
		0xfe, 0x80, 0x01,
	}

	_, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	answer, _, erra := DecodeAnswer(1, offset, payload)
	if erra != nil {
		t.Errorf("unexpected error while decoding answer: %v", erra)
	}
	// parsing answers should skip the OPT type and not return anything from
	// the additional section
	if len(answer) > 0 {
		t.Errorf("did not expect any answers to be parsed, got %d", len(answer))
	}
	_, _, erre := DecodeEDNS(1, offset, payload)

	if !errors.Is(erre, ErrDecodeEdnsOptionCsubnetBadFamily) {
		t.Errorf("bad error returned: %v", erre)
	}
}

func TestDecodeQuery_EdnsSubnet_Short(t *testing.T) {
	payload := []byte{
		// header
		0xe9, 0x9d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Additional records section
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x06,
		//RDATA
		// CODE - Client subnet
		0x00, 0x08,
		// Length
		0x00, 0x02,
		// Option data
		// family
		0x00, 0x01,
		// prefix-len
		// 0x18,
		// // scope prefix-len
		// 0x00,
		// // address
		// 0xfe, 0x80, 0x01,
	}

	_, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	answer, _, erra := DecodeAnswer(1, offset, payload)
	if erra != nil {
		t.Errorf("unexpected error while decoding answer: %v", erra)
	}
	// parsing answers should skip the OPT type and not return anything from
	// the additional section
	if len(answer) > 0 {
		t.Errorf("did not expect any answers to be parsed, got %d", len(answer))
	}
	_, _, erre := DecodeEDNS(1, offset, payload)

	if !errors.Is(erre, ErrDecodeEdnsOptionTooShort) {
		t.Errorf("bad error returned: %v", erre)
	}
}

func TestDecodeQuery_EdnsSubnet_NoAddr(t *testing.T) {
	payload := []byte{
		// header
		0xe9, 0x9d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Additional records section
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x08,
		//RDATA
		// CODE - Client subnet
		0x00, 0x08,
		// Length
		0x00, 0x04,
		// Option data
		// family
		0x00, 0x01,
		//prefix-len
		0x18,
		// scope prefix-len
		0x00,
		// // address
		// 0xfe, 0x80, 0x01,
	}

	_, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	answer, _, erra := DecodeAnswer(1, offset, payload)
	if erra != nil {
		t.Errorf("unexpected error while decoding answer: %v", erra)
	}
	// parsing answers should skip the OPT type and not return anything from
	// the additional section
	if len(answer) > 0 {
		t.Errorf("did not expect any answers to be parsed, got %d", len(answer))
	}

	edns, _, erre := DecodeEDNS(1, offset, payload)
	if erre != nil {
		t.Errorf("unexpected error while decoding EDNS: %v", erre)
	}

	expected := DnsOption{Code: 0x0008, Name: OptCodeToString(0x0008), Data: "0.0.0.0/24"}

	if len(edns.Options) != 1 {
		t.Errorf("expected one EDNS option, got %d", len(edns.Options))
	}

	if edns.Options[0] != expected {
		t.Errorf("unexpected option parsed from EDNS, expected %v got %v", expected, edns.Options[0])
	}

}

func TestDecodeAnswer_EdnsError(t *testing.T) {
	payload := []byte{
		// header
		0xe9, 0x9d, 0x81, 0x82, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Additional records section
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x06,
		//RDATA
		// CODE - Extended error
		0x00, 0x0f,
		// Length
		0x00, 0x02,
		// Option data
		// Error code
		0x00, 0x17,
	}

	_, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	edns, _, erre := DecodeEDNS(1, offset, payload)
	if erre != nil {
		t.Errorf("unexpected error while decoding edns: %v", erre)
	}

	if edns.Do != 1 || edns.Z != 0 || edns.Version != 0 || edns.UdpSize != 1232 || edns.ExtendedRcode != 0 {
		t.Errorf("invalid data in parsed EDNS header: %v", edns)
	}

	if len(edns.Options) != 1 {
		t.Errorf("expected one edns option to be parsed, got %d", len(edns.Options))
	}
	expected := DnsOption{Code: 0x000f, Name: OptCodeToString(0x000f), Data: "23 Network Error -"}
	if edns.Options[0] != expected {
		t.Errorf("bad edns option, expected %v, got %v", expected, edns.Options[0])
	}

}
func TestDecodeAnswer_EdnsErrorText(t *testing.T) {
	payload := []byte{
		// header
		0xe9, 0x9d, 0x81, 0x82, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Additional records section
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x0c,
		//RDATA
		// CODE - Extended error
		0x00, 0x0f,
		// Length
		0x00, 0x08,
		// Option data
		// Error code
		0x00, 0x17,
		// Error text
		0x62, 0x30, 0x72, 0x6b, 0x65, 0x6e,
	}

	_, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	edns, _, erre := DecodeEDNS(1, offset, payload)
	if erre != nil {
		t.Errorf("unexpected error while decoding edns: %v", erre)
	}

	if edns.Do != 1 || edns.Z != 0 || edns.Version != 0 || edns.UdpSize != 1232 || edns.ExtendedRcode != 0 {
		t.Errorf("invalid data in parsed EDNS header: %v", edns)
	}

	if len(edns.Options) != 1 {
		t.Errorf("expected one edns option to be parsed, got %d", len(edns.Options))
	}
	expected := DnsOption{Code: 0x000f, Name: OptCodeToString(0x000f), Data: "23 Network Error b0rken"}
	if edns.Options[0] != expected {
		t.Errorf("bad edns option, expected %v, got %v", expected, edns.Options[0])
	}

}

func TestDecodeAnswer_EdnsErrorShort(t *testing.T) {
	payload := []byte{
		// header
		0xe9, 0x9d, 0x81, 0x82, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query section
		0x0b, 0x73, 0x65, 0x6e,
		0x73, 0x6f, 0x72, 0x66, 0x6c, 0x65, 0x65, 0x74,
		0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Additional records section
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x05,
		//RDATA
		// CODE - Extended error
		0x00, 0x0f,
		// Length
		0x00, 0x01,
		// Option data
		// Error code, missing byte
		0x00,
	}

	_, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	_, _, erre := DecodeEDNS(1, offset, payload)
	if !errors.Is(erre, ErrDecodeEdnsOptionTooShort) {
		t.Errorf("bad error returned: %v", erre)
	}
}

func TestDecodeEdns_Short(t *testing.T) {
	testData := []struct {
		name          string
		input         []byte
		expectedError error
	}{{
		"empty", []byte{},
		ErrDecodeDnsLabelTooShort,
	},
		{
			"short", []byte{
				// empty name
				0x00,
			},
			ErrDecodeDnsAnswerTooShort,
		},
		{
			"invalid rdlength",
			[]byte{
				// empty name
				0x00,
				// type OPT
				0x00, 0x29,
				// class / UDP Payload size
				0x04, 0xd0,
				// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
				0x00, 0x00, 0x80, 0x00,
				// RDLENGTH
				0x00, 0x10,
				//RDATA
				// CODE - Extended error
				0x00, 0x0f,
				// Length
				0x00, 0x00,
				// Option data
				0x00,
			},
			ErrDecodeEdnsDataTooShort,
		},
		{
			"short-option",
			[]byte{
				// empty name
				0x00,
				// type OPT
				0x00, 0x29,
				// class / UDP Payload size
				0x04, 0xd0,
				// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
				0x00, 0x00, 0x80, 0x00,
				// RDLENGTH
				0x00, 0x02,
				//RDATA
				// CODE - Extended error
				0x00, 0x0f,
			},
			ErrDecodeEdnsOptionTooShort,
		},
		{
			"invalid-optlen",
			[]byte{
				// empty name
				0x00,
				// type OPT
				0x00, 0x29,
				// class / UDP Payload size
				0x04, 0xd0,
				// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
				0x00, 0x00, 0x80, 0x00,
				// RDLENGTH
				0x00, 0x05,
				//RDATA
				// CODE - Extended error
				0x00, 0x0f,
				// Length
				0x00, 0x05,
				// Option data
				0x00, 0x00, 0x00,
			},
			ErrDecodeEdnsDataTooShort,
		},
		{
			"read-past-rdata",
			[]byte{
				// empty name
				0x00,
				// type OPT
				0x00, 0x29,
				// class / UDP Payload size
				0x04, 0xd0,
				// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
				0x00, 0x00, 0x80, 0x00,
				// RDLENGTH
				0x00, 0x05,
				//RDATA
				// CODE - Extended error
				0x00, 0x0f,
				// Length
				0x00, 0x0e,
				// Option data
				0x00, 0x00, 0x00,
				// Another RR starts here, we try to trick the parser
				// to jum here with invalid option length
				// empty name
				0x00,
				// type OPT
				0x00, 0x29,
				// class / UDP Payload size
				0x04, 0xd0,
				// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
				0x00, 0x00, 0x80, 0x00,
				// RDLENGTH
				0x00, 0x07,
				//RDATA
				// CODE - Extended error
				0x00, 0x0f,
				// Length
				0x00, 0x03,
				// Option data
				0x00, 0x00, 0x00,
			},
			ErrDecodeEdnsDataTooShort,
		},
		{
			"invalid-name",
			[]byte{
				//  name
				0x01, 0x61, 0x00,
				// type OPT
				0x00, 0x29,
				// class / UDP Payload size
				0x04, 0xd0,
				// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
				0x00, 0x00, 0x80, 0x00,
				// RDLENGTH
				0x00, 0x06,
				//RDATA
				// CODE - Extended error
				0x00, 0x0f,
				// Length
				0x00, 0x03,
				// Option data
				0x00, 0x00,
			},
			ErrDecodeEdnsBadRootDomain,
		},
	}

	for _, test := range testData {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := DecodeEDNS(1, 0, test.input)
			if !errors.Is(err, test.expectedError) {
				t.Errorf("bad error: %v, expected: %v", err, test.expectedError)
			}
		})
	}
}

func TestDecodeEdns_MultipleOpts(t *testing.T) {
	payload := []byte{
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x06,
		//RDATA
		// CODE - Extended error
		0x00, 0x0f,
		// Length
		0x00, 0x02,
		// Option data
		0x00, 0x00,
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=0, Z=1
		0x00, 0x00, 0x00, 0x01,
		// RDLENGTH
		0x00, 0x06,
		//RDATA
		// CODE - Extended error
		0x00, 0x0f,
		// Length
		0x00, 0x02,
		// Option data
		0x00, 0x01,
	}

	_, _, err := DecodeEDNS(2, 0, payload)
	if !errors.Is(err, ErrDecodeEdnsTooManyOpts) {
		t.Errorf("bad error received: %v", err)
	}
}

func TestDecodeEdns_NonEDNSFollows(t *testing.T) {
	payload := []byte{
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x00,
		// no RDATA
		// next RR,
		// Name
		0x03, 0x46, 0x4f, 0x4f, 0x03, 0x4e, 0x45, 0x54, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x04,
		// RDATA 127.0.0.1
		0x7f, 0x00, 0x00, 0x01,
	}

	edns, offset, err := DecodeEDNS(2, 0x00, payload)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if offset != len(payload) {
		t.Errorf("expected offset %d, got %d", len(payload), offset)
	}
	if len(edns.Options) != 0 {
		t.Errorf("Did not expect any Options on EDNS")
	}
	if edns.UdpSize != 1232 {
		t.Errorf("expected UDP Size of 1232, got %d", edns.UdpSize)
	}
}

func TestDecodeEdns_EDNSFollows(t *testing.T) {
	payload := []byte{
		0x03, 0x46, 0x4f, 0x4f, 0x03, 0x4e, 0x45, 0x54, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x04,
		// RDATA 127.0.0.1
		0x7f, 0x00, 0x00, 0x01,
		// EDNS DATA
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x00,
	}

	edns, offset, err := DecodeEDNS(2, 0x00, payload)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if offset != len(payload) {
		t.Errorf("expected offset %d, got %d", len(payload), offset)
	}
	if len(edns.Options) != 0 {
		t.Errorf("Did not expect any Options on EDNS")
	}
	if edns.UdpSize != 1232 {
		t.Errorf("expected UDP Size of 1232, got %d", edns.UdpSize)
	}
}

func TestDecodeEdns_invalidRRFollows(t *testing.T) {
	payload := []byte{
		// empty name
		0x00,
		// type OPT
		0x00, 0x29,
		// class / UDP Payload size
		0x04, 0xd0,
		// TTL /  EXT-RCODE=0, VERSION=0, DO=1, Z=0
		0x00, 0x00, 0x80, 0x00,
		// RDLENGTH
		0x00, 0x00,
		// no RDATA
		// next RR,
		// Name
		0x03, 0x46, 0x4f, 0x4f, 0x03, 0x4e, 0x45, 0x54, 0x00,
		// type A, class IN
		0x00, 0x01, 0x00, 0x01,
		// TTL
		0x00, 0x00, 0x0e, 0x10,
		// RDLENGTH
		0x00, 0x04,
		// not enough RDATA
		0x7f, 0x00,
	}

	_, _, err := DecodeEDNS(2, 0x00, payload)
	if !errors.Is(err, ErrDecodeEdnsDataTooShort) {
		t.Errorf("bad error received: %v", err)
	}
}
