package dnsutils

import "crypto/tls"

const (
	STR_UNKNOWN = "UNKNOWN"

	PROG_NAME    = "dnscollector"
	LOCALHOST_IP = "127.0.0.1"

	MODE_TEXT = "text"
	MODE_JSON = "json"

	DNSTAP_CLIENT_RESPONSE = "CLIENT_RESPONSE"
	DNSTAP_CLIENT_QUERY    = "CLIENT_QUERY"

	PROTO_IPV6 = "INIT6"
	PROTO_IPV4 = "INIT"
	PROTO_UDP  = "UDP"
	PROTO_TCP  = "TCP"

	SOCKET_TCP  = "tcp"
	SOCKET_UDP  = "udp"
	SOCKET_UNIX = "unix"

	TLS_v10 = "1.0"
	TLS_v11 = "1.1"
	TLS_v12 = "1.2"
	TLS_v13 = "1.3"
)

var (
	TLS_VERSION = map[string]uint16{
		TLS_v10: tls.VersionTLS10,
		TLS_v11: tls.VersionTLS11,
		TLS_v12: tls.VersionTLS12,
		TLS_v13: tls.VersionTLS13,
	}
)
