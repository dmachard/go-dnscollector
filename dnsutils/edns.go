package dnsutils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

var ErrDecodeEdnsBadRootDomain = errors.New("edns, name MUST be 0 (root domain)")
var ErrDecodeEdnsDataTooShort = errors.New("edns, not enough data to decode rdata answer")
var ErrDecodeEdnsOptionTooShort = errors.New("edns, not enough data to decode option answer")
var ErrDecodeEdnsOptionCsubnetBadFamily = errors.New("edns, csubnet option bad family")
var ErrDecodeEdnsTooManyOpts = errors.New("edns, packet contained too many OPT RRs")

var (
	OptCodes = map[int]string{
		3:  "NSID",
		8:  "CSUBNET",
		9:  "EXPIRE",
		10: "COOKIE",
		11: "KEEPALIVE",
		12: "PADDING",
		15: "ERRORS",
	}
	ErrorCodeToString = map[int]string{
		0:  "Other",
		1:  "Unsupported DNSKEY Algorithm",
		2:  "Unsupported DS Digest Type",
		3:  "Stale Answer",
		4:  "Forged Answer",
		5:  "DNSSEC Indeterminate",
		6:  "DNSSEC Bogus",
		7:  "Signature Expired",
		8:  "Signature Not Yet Valid",
		9:  "DNSKEY Missing",
		10: "RRSIGs Missing",
		11: "No Zone Key Bit Set",
		12: "NSEC Missing",
		13: "Cached Error",
		14: "Not Ready",
		15: "Blocked",
		16: "Censored",
		17: "Filtered",
		18: "Prohibited",
		19: "Stale NXDOMAIN Answer",
		20: "Not Authoritative",
		21: "Not Supported",
		22: "No Reachable Authority",
		23: "Network Error",
		24: "Invalid Data",
	}
)

func OptCodeToString(rcode int) string {
	if value, ok := OptCodes[rcode]; ok {
		return value
	}
	return STR_UNKNOWN
}

func DecodeEDNS(arcount int, start_offset int, payload []byte) (DnsExtended, int, error) {
	offset := start_offset
	edns := DnsExtended{}
	options := []DnsOption{}
	ednsFound := false

	for i := 0; i < arcount; i++ {
		// Decode NAME
		name, offset_next, err := ParseLabels(offset, payload)
		if err != nil {
			return edns, offset, err
		}
		// before to continue, check we have enough data
		if len(payload[offset_next:]) < 10 {
			return edns, offset, ErrDecodeDnsAnswerTooShort
		}
		// decode TYPE, take in account only OPT option
		t := binary.BigEndian.Uint16(payload[offset_next : offset_next+2])
		if t == 41 {
			// RFC 6891 says "When an OPT RR is included within any DNS message, it MUST be the
			// only OPT RR in that message."
			if ednsFound {
				return edns, offset, ErrDecodeEdnsTooManyOpts
			}
			// checking domain name, MUST be 0 (root domain)
			if len(name) > 0 {
				return edns, offset, ErrDecodeEdnsBadRootDomain
			}

			// decode udp payload size
			edns.UdpSize = int(binary.BigEndian.Uint16(payload[offset_next+2 : offset_next+4]))

			/* decode extended rcode and flags
			    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			0:  |         EXTENDED-RCODE        |            VERSION            |
			    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			2:  | DO|                           Z                               |
			    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+ */
			// Extended rcode is equal to the upper 8 bits
			edns.ExtendedRcode = int(binary.BigEndian.Uint32(payload[offset_next+4:offset_next+8])&0xFF000000>>24) << 4
			edns.Version = int(binary.BigEndian.Uint32(payload[offset_next+4:offset_next+8]) & 0x00FF0000 >> 16)
			edns.Do = int(binary.BigEndian.Uint32(payload[offset_next+4:offset_next+8]) & 0x00008000 >> 0xF)
			edns.Z = int(binary.BigEndian.Uint32(payload[offset_next+4:offset_next+8]) & 0x7FFF)

			// decode RDLENGTH
			rdlength := binary.BigEndian.Uint16(payload[offset_next+8 : offset_next+10])
			if len(payload[offset_next+10:]) < int(rdlength) {
				return edns, offset, ErrDecodeEdnsDataTooShort
			}

			/* now we can decode all options, pairs of attribute/values
			                +0 (MSB)                            +1 (LSB)
			   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			0: |                          OPTION-CODE                          |
			   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			2: |                         OPTION-LENGTH                         |
			   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			4: |                                                               |
			   /                          OPTION-DATA                          /
			   /                                                               /
			   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+ */
			end_offset := offset_next + 10 + int(rdlength)
			offset_next = offset_next + 10

			for {
				// no more options to read ?
				if offset_next >= end_offset {
					break
				}

				// check that we can read code and length
				if end_offset-offset_next < 4 {
					return edns, offset, ErrDecodeEdnsOptionTooShort
				}

				optCode := int(binary.BigEndian.Uint16(payload[offset_next : offset_next+2]))
				optLength := int(binary.BigEndian.Uint16(payload[offset_next+2 : offset_next+4]))
				// ensure there is enough data on RDATA for this option
				if offset_next+4+optLength > end_offset {
					return edns, offset, ErrDecodeEdnsDataTooShort
				}

				optName := OptCodeToString(optCode)
				optString, err := ParseOption(optName, payload[offset_next+4:offset_next+4+optLength])
				if err != nil {
					return edns, offset, err
				}
				// create option
				o := DnsOption{
					Code: optCode,
					Name: optName,
					Data: optString,
				}
				options = append(options, o)

				// compute next offset
				offset_next = offset_next + 4 + optLength
			}

			edns.Options = options
			ednsFound = true
			offset = offset_next

		} else {
			// advance to next RR
			rdlength := binary.BigEndian.Uint16(payload[offset_next+8 : offset_next+10])
			if len(payload[offset_next+10:]) < int(rdlength) {
				return edns, offset, ErrDecodeEdnsDataTooShort
			}
			offset = offset_next + 10 + int(rdlength)
		}
	}
	return edns, offset, nil
}

func ParseOption(optName string, optData []byte) (string, error) {
	var ret string
	var err error
	switch optName {
	case "ERRORS":
		ret, err = ParseErrors(optData)
	case "CSUBNET":
		ret, err = ParseCsubnet(optData)
	default:
		ret = "-"
		err = nil
	}
	return ret, err
}

/*
https://datatracker.ietf.org/doc/html/rfc8914

Extended Error EDNS0 option format
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| INFO-CODE                                                     |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/ EXTRA-TEXT ...                                                /
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
*/
func ParseErrors(d []byte) (string, error) {
	if len(d) < 2 {
		return "", ErrDecodeEdnsOptionTooShort
	}
	code := int(binary.BigEndian.Uint16(d[:2]))
	infoCode := ""
	if s, ok := ErrorCodeToString[code]; ok {
		infoCode = fmt.Sprintf("%d %s", code, s)
	} else {
		infoCode = fmt.Sprintf("%d -", code)
	}

	extraText := "-"
	if len(d[2:]) > 0 {
		extraText = string(d[2:])
	}

	opt := fmt.Sprintf("%s %s", infoCode, extraText)
	return opt, nil
}

/*
	https://datatracker.ietf.org/doc/html/rfc7871

	Extended Csubnet EDNS0 option format
	                                            1   1   1   1   1   1
	    0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
	  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

4: |                            FAMILY                             |

	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

6: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |

	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

8: |                           ADDRESS...                          /

	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
*/
func ParseCsubnet(d []byte) (string, error) {
	if len(d) < 4 {
		return "", ErrDecodeEdnsOptionTooShort
	}
	family := int(binary.BigEndian.Uint16(d[:2]))
	srcMask := d[2]
	switch family {
	case 1:
		addr := make(net.IP, net.IPv4len)
		copy(addr, d[4:])
		ecs := fmt.Sprintf("%s/%d", addr.String(), srcMask)
		return ecs, nil
	case 2:
		addr := make(net.IP, net.IPv6len)
		copy(addr, d[4:])
		ecs := fmt.Sprintf("[%s]/%d", addr.String(), srcMask)
		return ecs, nil
	default:
		return "-", ErrDecodeEdnsOptionCsubnetBadFamily
	}
}
