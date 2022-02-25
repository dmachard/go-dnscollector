package subprocessors

import (
	"fmt"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"golang.org/x/net/publicsuffix"
)

// error returned if decoding of DNS packet payload fails.
type decodingError struct {
	part string
	err  error
}

func (e *decodingError) Error() string {
	return fmt.Sprintf("malformed %s in DNS packet: %v", e.part, e.err)
}

func (e *decodingError) Unwrap() error {
	return e.err
}

// decodePayload can be used to decode raw payload data in dm.DNS.Payload
// into relevant parts of dm.DNS struct. The payload is decoded according to
// given DNS header.
// qNamePrivacyEnabled should be set to true if query name privacy is enabled
// in configuration.
// If packet is marked as malformed already, this function returs with no
// error, but does not process the packet.
// Error is returned if packet can not be parsed. Returned error wraps the
// original error returned by relevant decoding operation.
func decodePayload(dm *dnsutils.DnsMessage, header *dnsutils.DnsHeader, qNamePrivacyEnabled bool, config *dnsutils.Config) error {

	if dm.DNS.MalformedPacket == 1 {
		// do not continue if packet is malformed, the header can not be
		// trusted.
		return nil
	}

	dm.DNS.Id = header.Id
	dm.DNS.Rcode = dnsutils.RcodeToString(header.Rcode)
	dm.DNS.Opcode = header.Opcode

	// update dnstap operation if the opcode is equal to 5 (dns update)
	if dm.DNS.Opcode == 5 && header.Qr == 1 {
		dm.DnsTap.Operation = "UPDATE_QUERY"
	}
	if dm.DNS.Opcode == 5 && header.Qr == 0 {
		dm.DnsTap.Operation = "UPDATE_RESPONSE"
	}

	if header.Qr == 1 {
		dm.DNS.Flags.QR = true
	}
	if header.Tc == 1 {
		dm.DNS.Flags.TC = true
	}
	if header.Aa == 1 {
		dm.DNS.Flags.AA = true
	}
	if header.Ra == 1 {
		dm.DNS.Flags.RA = true
	}
	if header.Ad == 1 {
		dm.DNS.Flags.AD = true
	}

	var payload_offset int
	// decode DNS question
	if header.Qdcount > 0 {
		dns_qname, dns_rrtype, offsetrr, err := dnsutils.DecodeQuestion(header.Qdcount, dm.DNS.Payload)
		if err != nil {
			dm.DNS.MalformedPacket = 1
			return &decodingError{part: "query", err: err}
		}
		if config.Subprocessors.QnameLowerCase {
			dm.DNS.Qname = strings.ToLower(dns_qname)
		} else {
			dm.DNS.Qname = dns_qname
		}

		// Public suffix
		ps, _ := publicsuffix.PublicSuffix(dm.DNS.Qname)
		dm.DNS.QnamePublicSuffix = ps

		if !qNamePrivacyEnabled {
			if etpo, err := publicsuffix.EffectiveTLDPlusOne(dm.DNS.Qname); err == nil {
				dm.DNS.QnameEffectiveTLDPlusOne = etpo
			}
		}

		dm.DNS.Qtype = dnsutils.RdatatypeToString(dns_rrtype)
		payload_offset = offsetrr
	}

	// decode DNS answers
	if header.Ancount > 0 {
		if answers, offset, err := dnsutils.DecodeAnswer(header.Ancount, payload_offset, dm.DNS.Payload); err == nil {
			dm.DNS.DnsRRs.Answers = answers
			payload_offset = offset
		} else {
			dm.DNS.MalformedPacket = 1
			return &decodingError{part: "answer records", err: err}
		}
	}

	// decode authoritative answers
	if header.Nscount > 0 {
		if answers, offsetrr, err := dnsutils.DecodeAnswer(header.Nscount, payload_offset, dm.DNS.Payload); err == nil {
			dm.DNS.DnsRRs.Nameservers = answers
			payload_offset = offsetrr
		} else {
			dm.DNS.MalformedPacket = 1
			return &decodingError{part: "authority records", err: err}
		}
	}
	if header.Arcount > 0 {
		// decode additional answers
		if answers, _, err := dnsutils.DecodeAnswer(header.Arcount, payload_offset, dm.DNS.Payload); err == nil {
			dm.DNS.DnsRRs.Records = answers
		} else {
			dm.DNS.MalformedPacket = 1
			return &decodingError{part: "additional records", err: err}
		}
		// decode EDNS options, if there are any
		if edns, _, err := dnsutils.DecodeEDNS(header.Arcount, payload_offset, dm.DNS.Payload); err == nil {
			dm.EDNS = edns
		} else {
			dm.DNS.MalformedPacket = 1
			return &decodingError{part: "edns options", err: err}
		}
	}
	return nil
}
