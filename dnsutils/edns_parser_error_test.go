package dnsutils

import (
	"errors"
	"testing"
)

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
		// RDATA
		// CODE - Extended error
		0x00, 0x0f,
		// Length
		0x00, 0x02,
		// Option data
		// Error code
		0x00, 0x17,
	}

	_, _, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	edns, _, erre := DecodeEDNS(1, offset, payload)
	if erre != nil {
		t.Errorf("unexpected error while decoding edns: %v", erre)
	}

	if edns.Do != 1 || edns.Z != 0 || edns.Version != 0 || edns.UDPSize != 1232 || edns.ExtendedRcode != 0 {
		t.Errorf("invalid data in parsed EDNS header: %v", edns)
	}

	if len(edns.Options) != 1 {
		t.Errorf("expected one edns option to be parsed, got %d", len(edns.Options))
	}
	expected := DNSOption{Code: 0x000f, Name: OptCodeToString(0x000f), Data: "23 Network Error -"}
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
		// RDATA
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

	_, _, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	edns, _, erre := DecodeEDNS(1, offset, payload)
	if erre != nil {
		t.Errorf("unexpected error while decoding edns: %v", erre)
	}

	if edns.Do != 1 || edns.Z != 0 || edns.Version != 0 || edns.UDPSize != 1232 || edns.ExtendedRcode != 0 {
		t.Errorf("invalid data in parsed EDNS header: %v", edns)
	}

	if len(edns.Options) != 1 {
		t.Errorf("expected one edns option to be parsed, got %d", len(edns.Options))
	}
	expected := DNSOption{Code: 0x000f, Name: OptCodeToString(0x000f), Data: "23 Network Error b0rken"}
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
		// RDATA
		// CODE - Extended error
		0x00, 0x0f,
		// Length
		0x00, 0x01,
		// Option data
		// Error code, missing byte
		0x00,
	}

	_, _, _, offset, err := DecodeQuestion(1, payload)
	if err != nil {
		t.Errorf("unexpected error while decoding question: %v", err)
	}

	_, _, erre := DecodeEDNS(1, offset, payload)
	if !errors.Is(erre, ErrDecodeEdnsOptionTooShort) {
		t.Errorf("bad error returned: %v", erre)
	}
}
