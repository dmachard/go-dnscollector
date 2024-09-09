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

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, _, err := DecodeEDNS(len(dm.Extra), offsetRR, payload)

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

	m.Extra = dm.Extra
	m.Extra = append(m.Extra, e)

	m.SetRcode(dm, 42) // 32(extended rcode) + 10(rcode)

	payload, _ := m.Pack()
	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, offsetRR, _ = DecodeAnswer(len(m.Answer), offsetRR, payload)

	_, _, err := DecodeEDNS(len(m.Extra), offsetRR, payload)
	if err != nil {
		t.Errorf("edns error returned: %v", err)
	}
}

func TestDecodeEdns_Short(t *testing.T) {
	testData := []struct {
		name          string
		input         []byte
		expectedError error
	}{{
		"empty", []byte{},
		ErrDecodeDNSLabelTooShort,
	},
		{
			"short", []byte{
				// empty name
				0x00,
			},
			ErrDecodeDNSAnswerTooShort,
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
				// RDATA
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
				// RDATA
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
				// RDATA
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
				// RDATA
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
				// RDATA
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
				// RDATA
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
		// RDATA
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
		// RDATA
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
	if edns.UDPSize != 1232 {
		t.Errorf("expected UDP Size of 1232, got %d", edns.UDPSize)
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
	if edns.UDPSize != 1232 {
		t.Errorf("expected UDP Size of 1232, got %d", edns.UDPSize)
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
