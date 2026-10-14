package dnsutils

import (
	"encoding/binary"
	"errors"
	"strconv"

	dnstap "github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-netutils"
)

var ErrInvalidDNSTapProtobuf = errors.New("invalid dnstap protobuf wire format")

// portToStringLookup is a static pre-computed table for all 65536 TCP/UDP ports.
// This provides an instant O(1) string lookup with zero heap allocation.
var portToStringLookup [65536]string

func init() {
	for i := 0; i < 65536; i++ {
		portToStringLookup[i] = strconv.Itoa(i)
	}
}

// FastPortToString returns the decimal string representation of a 16-bit port without allocation.
func FastPortToString(port uint32) string {
	if port < 65536 {
		return portToStringLookup[port]
	}
	return strconv.FormatUint(uint64(port), 10)
}

// inlineUvarint reads a protobuf varint with a fast-path for single-byte values (< 128).
// In Protobuf wire format, >95% of tags and small integers are encoded in a single byte.
func inlineUvarint(buf []byte) (uint64, int) {
	if len(buf) == 0 {
		return 0, 0
	}
	b := buf[0]
	if b < 0x80 {
		return uint64(b), 1
	}
	return binary.Uvarint(buf)
}

// DecodeDNSTapWire decodes a raw DNSTap Protobuf wire frame directly into a DNSMessage
// with zero heap allocations in the fast path.
func DecodeDNSTapWire(buf []byte, dm *DNSMessage) error {
	var (
		identityBytes    []byte
		versionBytes     []byte
		extraBytes       []byte
		msgType          uint64
		socketFamily     uint64
		socketProtocol   uint64
		queryIP          []byte
		responseIP       []byte
		queryPort        uint32
		responsePort     uint32
		queryTimeSec     uint64
		queryTimeNsec    uint32
		responseTimeSec  uint64
		responseTimeNsec uint32
		queryMessage     []byte
		responseMessage  []byte
		policyType       string
		policyRule       string
		policyAction     string
		policyMatch      string
		policyValue      string
		httpProtocol     string
		queryZone        []byte
	)

	// Scan top-level Dnstap message
	for len(buf) > 0 {
		tagWire, n := inlineUvarint(buf)
		if n <= 0 {
			return ErrInvalidDNSTapProtobuf
		}
		buf = buf[n:]
		wireType := tagWire & 7
		fieldNum := tagWire >> 3

		switch wireType {
		case 0: // Varint
			_, n := inlineUvarint(buf)
			if n <= 0 {
				return ErrInvalidDNSTapProtobuf
			}
			buf = buf[n:]
		case 2: // Length-delimited
			length, n := inlineUvarint(buf)
			if n <= 0 || int(length) > len(buf[n:]) {
				return ErrInvalidDNSTapProtobuf
			}
			val := buf[n : n+int(length)]
			buf = buf[n+int(length):]

			switch fieldNum {
			case 1: // identity
				identityBytes = val
			case 2: // version
				versionBytes = val
			case 3: // extra
				extraBytes = val
			case 14: // message sub-message
				sub := val
				for len(sub) > 0 {
					subTagWire, sn := inlineUvarint(sub)
					if sn <= 0 {
						return ErrInvalidDNSTapProtobuf
					}
					sub = sub[sn:]
					subWireType := subTagWire & 7
					subFieldNum := subTagWire >> 3

					switch subWireType {
					case 0: // Varint
						v, sn := inlineUvarint(sub)
						if sn <= 0 {
							return ErrInvalidDNSTapProtobuf
						}
						sub = sub[sn:]

						switch subFieldNum {
						case 1: // type
							msgType = v
						case 2: // socket_family
							socketFamily = v
						case 3: // socket_protocol
							socketProtocol = v
						case 6: // query_port
							queryPort = uint32(v)
						case 7: // response_port
							responsePort = uint32(v)
						case 8: // query_time_sec
							queryTimeSec = v
						case 12: // response_time_sec
							responseTimeSec = v
						case 16: // http_protocol enum
							httpProtocol = dnstap.HttpProtocol(v).String()
						}
					case 2: // Length-delimited
						slen, sn := inlineUvarint(sub)
						if sn <= 0 || int(slen) > len(sub[sn:]) {
							return ErrInvalidDNSTapProtobuf
						}
						sval := sub[sn : sn+int(slen)]
						sub = sub[sn+int(slen):]

						switch subFieldNum {
						case 4: // query_address
							queryIP = sval
						case 5: // response_address
							responseIP = sval
						case 10: // query_message
							queryMessage = sval
						case 11: // query_zone
							queryZone = sval
						case 14: // response_message
							responseMessage = sval
						case 15: // policy sub-message
							pol := sval
							for len(pol) > 0 {
								ptagWire, pn := inlineUvarint(pol)
								if pn <= 0 {
									return ErrInvalidDNSTapProtobuf
								}
								pol = pol[pn:]
								pwireType := ptagWire & 7
								pfieldNum := ptagWire >> 3

								switch pwireType {
								case 0: // Varint (Action/Match)
									pv, pn := inlineUvarint(pol)
									if pn <= 0 {
										return ErrInvalidDNSTapProtobuf
									}
									pol = pol[pn:]
									switch pfieldNum {
									case 3: // action
										policyAction = dnstap.Policy_Action(pv).String()
									case 4: // match
										policyMatch = dnstap.Policy_Match(pv).String()
									}
								case 2: // Length-delimited (Type, Rule, Value)
									plen, pn := inlineUvarint(pol)
									if pn <= 0 || int(plen) > len(pol[pn:]) {
										return ErrInvalidDNSTapProtobuf
									}
									pval := pol[pn : pn+int(plen)]
									pol = pol[pn+int(plen):]

									switch pfieldNum {
									case 1: // type
										policyType = string(pval)
									case 2: // rule
										policyRule = string(pval)
									case 5: // value
										policyValue = string(pval)
									}
								case 5:
									if len(pol) < 4 {
										return ErrInvalidDNSTapProtobuf
									}
									pol = pol[4:]
								case 1:
									if len(pol) < 8 {
										return ErrInvalidDNSTapProtobuf
									}
									pol = pol[8:]
								default:
									return ErrInvalidDNSTapProtobuf
								}
							}
						}
					case 5: // 32-bit (fixed32 query_time_nsec=9, response_time_nsec=13)
						if len(sub) < 4 {
							return ErrInvalidDNSTapProtobuf
						}
						v := binary.LittleEndian.Uint32(sub[:4])
						sub = sub[4:]
						switch subFieldNum {
						case 9:
							queryTimeNsec = v
						case 13:
							responseTimeNsec = v
						}
					case 1:
						if len(sub) < 8 {
							return ErrInvalidDNSTapProtobuf
						}
						sub = sub[8:]
					default:
						return ErrInvalidDNSTapProtobuf
					}
				}
			}
		case 5:
			if len(buf) < 4 {
				return ErrInvalidDNSTapProtobuf
			}
			buf = buf[4:]
		case 1:
			if len(buf) < 8 {
				return ErrInvalidDNSTapProtobuf
			}
			buf = buf[8:]
		default:
			return ErrInvalidDNSTapProtobuf
		}
	}

	if len(identityBytes) > 0 {
		dm.DNSTap.Identity = string(identityBytes)
	}
	if len(versionBytes) > 0 {
		dm.DNSTap.Version = string(versionBytes)
	}
	if len(extraBytes) > 0 {
		dm.DNSTap.Extra = string(extraBytes)
	}

	// Operation
	switch dnstap.Message_Type(msgType) {
	case dnstap.Message_AUTH_QUERY:
		dm.DNSTap.Operation = "AUTH_QUERY"
	case dnstap.Message_AUTH_RESPONSE:
		dm.DNSTap.Operation = "AUTH_RESPONSE"
	case dnstap.Message_RESOLVER_QUERY:
		dm.DNSTap.Operation = "RESOLVER_QUERY"
	case dnstap.Message_RESOLVER_RESPONSE:
		dm.DNSTap.Operation = "RESOLVER_RESPONSE"
	case dnstap.Message_CLIENT_QUERY:
		dm.DNSTap.Operation = "CLIENT_QUERY"
	case dnstap.Message_CLIENT_RESPONSE:
		dm.DNSTap.Operation = "CLIENT_RESPONSE"
	case dnstap.Message_FORWARDER_QUERY:
		dm.DNSTap.Operation = "FORWARDER_QUERY"
	case dnstap.Message_FORWARDER_RESPONSE:
		dm.DNSTap.Operation = "FORWARDER_RESPONSE"
	case dnstap.Message_STUB_QUERY:
		dm.DNSTap.Operation = "STUB_QUERY"
	case dnstap.Message_STUB_RESPONSE:
		dm.DNSTap.Operation = "STUB_RESPONSE"
	case dnstap.Message_TOOL_QUERY:
		dm.DNSTap.Operation = "TOOL_QUERY"
	case dnstap.Message_TOOL_RESPONSE:
		dm.DNSTap.Operation = "TOOL_RESPONSE"
	default:
		dm.DNSTap.Operation = "UNKNOWN"
	}

	// Family
	switch dnstap.SocketFamily(socketFamily) {
	case dnstap.SocketFamily_INET:
		dm.NetworkInfo.Family = netutils.ProtoIPv4
	case dnstap.SocketFamily_INET6:
		dm.NetworkInfo.Family = netutils.ProtoIPv6
	default:
		if len(queryIP) == 4 || len(responseIP) == 4 {
			dm.NetworkInfo.Family = netutils.ProtoIPv4
		} else if len(queryIP) == 16 || len(responseIP) == 16 {
			dm.NetworkInfo.Family = netutils.ProtoIPv6
		} else {
			dm.NetworkInfo.Family = "UNKNOWN"
		}
	}

	// Protocol
	switch dnstap.SocketProtocol(socketProtocol) {
	case dnstap.SocketProtocol_UDP:
		dm.NetworkInfo.Protocol = "UDP"
	case dnstap.SocketProtocol_TCP:
		dm.NetworkInfo.Protocol = "TCP"
	case dnstap.SocketProtocol_DOT:
		dm.NetworkInfo.Protocol = "DOT"
	case dnstap.SocketProtocol_DOH:
		dm.NetworkInfo.Protocol = "DOH"
	case dnstap.SocketProtocol_DNSCryptUDP:
		dm.NetworkInfo.Protocol = "DNSCryptUDP"
	case dnstap.SocketProtocol_DNSCryptTCP:
		dm.NetworkInfo.Protocol = "DNSCryptTCP"
	case dnstap.SocketProtocol_DOQ:
		dm.NetworkInfo.Protocol = "DOQ"
	default:
		dm.NetworkInfo.Protocol = "UNKNOWN"
	}

	// Addresses and Ports
	if len(queryIP) > 0 {
		n := copy(dm.NetworkInfo.QueryIPBuf[:], queryIP)
		dm.NetworkInfo.QueryIPLen = uint8(n)
	}
	if queryPort > 0 {
		dm.NetworkInfo.QueryPort = FastPortToString(queryPort)
	}

	if len(responseIP) > 0 {
		n := copy(dm.NetworkInfo.ResponseIPBuf[:], responseIP)
		dm.NetworkInfo.ResponseIPLen = uint8(n)
	}
	if responsePort > 0 {
		dm.NetworkInfo.ResponsePort = FastPortToString(responsePort)
	}

	// DNS Payload and Timestamps
	op := int(msgType)
	if op%2 == 1 {
		dm.DNS.Payload = queryMessage
		dm.DNS.Length = len(queryMessage)
		dm.DNS.Type = DNSQuery
		dm.DNSTap.TimeSec = int(queryTimeSec)
		dm.DNSTap.TimeNsec = int(queryTimeNsec)
	} else {
		dm.DNS.Payload = responseMessage
		dm.DNS.Length = len(responseMessage)
		dm.DNS.Type = DNSReply
		dm.DNSTap.TimeSec = int(responseTimeSec)
		dm.DNSTap.TimeNsec = int(responseTimeNsec)

		tsQuery := float64(queryTimeSec) + float64(queryTimeNsec)/1e9
		tsReply := float64(responseTimeSec) + float64(responseTimeNsec)/1e9

		if tsQuery != 0 && tsReply >= tsQuery {
			dm.DNSTap.Latency = tsReply - tsQuery
			dm.DNSTap.LatencyMs = int((tsReply - tsQuery) * 1000)
		}
	}

	// Policy and HTTP protocol
	if len(policyType) > 0 {
		dm.DNSTap.PolicyType = policyType
	}
	if len(policyRule) > 0 {
		dm.DNSTap.PolicyRule = policyRule
	}
	if len(policyAction) > 0 {
		dm.DNSTap.PolicyAction = policyAction
	}
	if len(policyMatch) > 0 {
		dm.DNSTap.PolicyMatch = policyMatch
	}
	if len(policyValue) > 0 {
		dm.DNSTap.PolicyValue = policyValue
	}
	if len(httpProtocol) > 0 {
		dm.DNSTap.HttpProtocol = httpProtocol
	}

	// Query Zone
	if len(queryZone) > 0 {
		qz, _, err := ParseLabels(0, queryZone, true)
		if err == nil {
			dm.DNSTap.QueryZone = qz
		}
	}

	return nil
}
