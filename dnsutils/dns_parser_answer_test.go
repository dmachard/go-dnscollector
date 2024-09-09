package dnsutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

func TestDecodeAnswer_Ns(t *testing.T) {
	fqdn := TestQName

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
	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, offsetRRns, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

	nsAnswers, _, _ := DecodeAnswer(len(m.Ns), offsetRRns, payload)
	if len(nsAnswers) != len(m.Ns) {
		t.Errorf("invalid decode answer, want %d, got: %d", len(m.Ns), len(nsAnswers))
	}
}

func TestDecodeAnswer(t *testing.T) {
	fqdn := TestQName

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)
	rr1, _ := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", fqdn))
	rr2, _ := dns.NewRR(fmt.Sprintf("%s A 127.0.0.2", fqdn))
	dm.Answer = append(dm.Answer, rr1)
	dm.Answer = append(dm.Answer, rr2)

	payload, _ := dm.Pack()

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	answer, _, _ := DecodeAnswer(len(dm.Answer), offsetRR, payload)

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

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, _, err := DecodeAnswer(4, offsetRR, payload)
	if err != nil {
		t.Errorf("failed to decode valid dns packet with minimization")
	}
}

func TestDecodeDnsAnswer_PacketTooShort(t *testing.T) {
	payload := []byte{46, 172, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0}

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, _, err := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(err, ErrDecodeDNSAnswerTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_PathologicalPacket(t *testing.T) {
	// Create a message with one question and `n` answers (`n` determined later).
	decoded := make([]byte, 65500)
	copy(decoded, []byte{88, 27, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	// Create a rather suboptimal name for the question.
	// The answers point to this a bajillion times later.
	// This name breaks several rules:v
	//  * Label length is > 63
	//  * Name length is > 255 bytes
	//  * Pointers jump all over the place, not just backwards
	i := 12
	for {
		// Create a bunch of interleaved labels of length 191,
		// each label immediately followed by a pointer to the
		// label next to it. The last label of the interleaved chunk
		// is followed with a pointer to forwards to the next chunk
		// of interleaved labels:
		//
		// [191 ... 191 ... 191 ... ... ptr1 ptr2 ... ptrN 191 ... 191 ...]
		//           ^      ^            │    │        │    ^
		//           │      └────────────┼────┘        └────┘
		//           └───────────────────┘
		//
		// We then repeat this pattern as many times as we can within the
		// first 16383 bytes (so that we can point to it later).
		// Then cleanly closing the name with a null byte in the end allows us to
		// create a name of around 700 kilobytes (I checked once, don't quote me on this).
		if 16384-i < 384 {
			decoded[i] = 0
			break
		}
		for j := 0; j < 192; j += 2 {
			decoded[i] = 191
			i += 2
		}
		for j := 0; j < 190; j += 2 {
			offset := i - 192 + 2
			decoded[i] = 0xc0 | byte(offset>>8)
			decoded[i+1] = byte(offset & 0xff)
			i += 2
		}
		offset := i + 2
		decoded[i] = 0xc0 | byte(offset>>8)
		decoded[i+1] = byte(offset & 0xff)
		i += 2
	}

	// Fill in the rest of the question
	copy(decoded[i:], []byte{0, 5, 0, 1})
	i += 4

	// Fit as many answers as we can that contain CNAME RDATA pointing to
	// the bloated name created above.
	ancount := 0
	for j := i; j+13 <= len(decoded); j += 13 {
		copy(decoded[j:], []byte{0, 0, 5, 0, 0, 0, 0, 0, 1, 0, 2, 192, 12})
		ancount += 1
	}

	// Update the message with the answer count
	decoded[6] = byte(ancount >> 8)
	decoded[7] = byte(ancount & 0xff)

	_, _, err := DecodeAnswer(ancount, i, decoded)
	if !errors.Is(err, ErrDecodeDNSLabelInvalidData) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_RdataTooShort(t *testing.T) {
	payload := []byte{46, 172, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 127, 0}

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, _, err := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(err, ErrDecodeDNSAnswerRdataTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_InvalidPtr(t *testing.T) {
	payload := []byte{128, 177, 129, 160, 0, 1, 0, 1, 0, 0, 0, 1, 5, 104, 101, 108, 108, 111, 4,
		109, 99, 104, 100, 2, 109, 101, 0, 0, 1, 0, 1, 192, 254, 0, 1, 0, 1, 0, 0,
		14, 16, 0, 4, 83, 112, 146, 176}

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, _, err := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(err, ErrDecodeDNSLabelInvalidPointer) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_InvalidPtr_Loop1(t *testing.T) {
	// loop qname on himself
	payload := []byte{128, 177, 129, 160, 0, 1, 0, 1, 0, 0, 0, 1, 5, 104, 101, 108, 108, 111, 4,
		109, 99, 104, 100, 2, 109, 101, 0, 0, 1, 0, 1, 192, 31, 0, 1, 0, 1, 0, 0,
		14, 16, 0, 4, 83, 112, 146, 176}

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, _, err := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(err, ErrDecodeDNSLabelInvalidPointer) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestDecodeDnsAnswer_InvalidPtr_Loop2(t *testing.T) {
	// loop between qnames
	payload := []byte{128, 177, 129, 160, 0, 1, 0, 2, 0, 0, 0, 1, 5, 104, 101, 108, 108, 111, 4,
		109, 99, 104, 100, 2, 109, 101, 0, 0, 1, 0, 1, 192, 47, 0, 1, 0, 1, 0, 0,
		14, 16, 0, 4, 83, 112, 146, 176, 192, 31, 0, 1, 0, 1, 0, 0,
		14, 16, 0, 4, 83, 112, 146, 176}

	_, _, _, offsetRR, _ := DecodeQuestion(1, payload)
	_, _, err := DecodeAnswer(1, offsetRR, payload)
	if !errors.Is(err, ErrDecodeDNSLabelInvalidPointer) {
		t.Errorf("bad error returned: %v", err)
	}
}
