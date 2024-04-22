package netutils

const (
	ProtoInet  = "INET"
	ProtoInet6 = "INET6"
	ProtoIPv6  = "IPv6"
	ProtoIPv4  = "IPv4"

	ProtoUDP = "UDP"
	ProtoTCP = "TCP"

	SocketTCP  = "tcp"
	SocketUDP  = "udp"
	SocketUnix = "unix"
	SocketTLS  = "tcp+tls"
)

var (
	IPVersion = map[string]string{
		ProtoInet:  ProtoIPv4,
		ProtoInet6: ProtoIPv6,
	}

	IPToInet = map[string]string{
		ProtoIPv4: ProtoInet,
		ProtoIPv6: ProtoInet6,
	}
)
