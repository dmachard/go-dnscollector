package dnsutils

import (
	"errors"
	"testing"
)

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
		// RDATA
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

	_, _, _, offset, err := DecodeQuestion(1, payload)
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
	if edns.Do != 1 || edns.Z != 0 || edns.Version != 0 || edns.UDPSize != 1232 || edns.ExtendedRcode != 0 {
		t.Errorf("invalid data in parsed EDNS header: %v", edns)
	}

	if len(edns.Options) != 1 {
		t.Errorf("expected 1 EDNS option to be parsed, got %v", len(edns.Options))
	}

	expectedOption := DNSOption{Code: 0x0008, Name: OptCodeToString(0x0008), Data: "192.168.1.0/24"}

	if edns.Options[0] != expectedOption {
		t.Errorf("bad option parsed, expected %v, got %v", expectedOption, edns.Options[0])
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
		// RDATA
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

	_, _, _, offset, err := DecodeQuestion(1, payload)
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
	if edns.Do != 1 || edns.Z != 0 || edns.Version != 0 || edns.UDPSize != 1232 || edns.ExtendedRcode != 0 {
		t.Errorf("invalid data in parsed EDNS header: %v", edns)
	}

	if len(edns.Options) != 1 {
		t.Errorf("expected 1 EDNS option to be parsed, got %v", len(edns.Options))
	}

	expectedOption := DNSOption{Code: 0x0008, Name: OptCodeToString(0x0008), Data: "[fe80:100::]/24"}

	if edns.Options[0] != expectedOption {
		t.Errorf("bad option parsed, expected %v, got %v", expectedOption, edns.Options[0])
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
		// RDATA
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

	_, _, _, offset, err := DecodeQuestion(1, payload)
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
		// RDATA
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

	_, _, _, offset, err := DecodeQuestion(1, payload)
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
		// RDATA
		// CODE - Client subnet
		0x00, 0x08,
		// Length
		0x00, 0x04,
		// Option data
		// family
		0x00, 0x01,
		// prefix-len
		0x18,
		// scope prefix-len
		0x00,
		// // address
		// 0xfe, 0x80, 0x01,
	}

	_, _, _, offset, err := DecodeQuestion(1, payload)
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

	expected := DNSOption{Code: 0x0008, Name: OptCodeToString(0x0008), Data: "0.0.0.0/24"}

	if len(edns.Options) != 1 {
		t.Errorf("expected one EDNS option, got %d", len(edns.Options))
	}

	if edns.Options[0] != expected {
		t.Errorf("unexpected option parsed from EDNS, expected %v got %v", expected, edns.Options[0])
	}

}
