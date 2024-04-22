package netutils

import (
	"encoding/binary"
	"net"
)

func ConvertIP4(ip uint32) net.IP {
	addr := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(addr, ip)
	return addr
}

func ConvertIP6(ip [4]uint32) net.IP {
	addr := make(net.IP, net.IPv6len)
	binary.LittleEndian.PutUint32(addr[0:], ip[0])
	binary.LittleEndian.PutUint32(addr[4:], ip[1])
	binary.LittleEndian.PutUint32(addr[8:], ip[2])
	binary.LittleEndian.PutUint32(addr[12:], ip[3])
	return addr
}

func GetIPAddress[T uint32 | [4]uint32](ip T, mapper func(T) net.IP) net.IP {
	return mapper(ip)
}
