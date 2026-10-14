package dnsutils

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"

	"github.com/dmachard/go-netutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	errEmptyPayload     = errors.New("payload is empty")
	errInvalidSrcPort   = errors.New("invalid source port value")
	errInvalidDstPort   = errors.New("invalid destination port value")
	errFamilyNotImpl    = errors.New("family not implemented")
	errProtocolNotImpl  = errors.New("protocol not implemented")
	errInvalidIPAddress = errors.New("invalid IP address")
)

func parseIPv4Bytes(s string, dst *[4]byte) bool {
	var acc, octet int
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if octet > 3 || acc > 255 {
				return false
			}
			dst[octet] = byte(acc)
			octet++
			acc = 0
		case c >= '0' && c <= '9':
			acc = acc*10 + int(c-'0')
		default:
			return false
		}
	}
	if octet != 3 || acc > 255 {
		return false
	}
	dst[3] = byte(acc)
	return true
}

func parseIPv6Bytes(s string, dst *[16]byte) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is6() {
		return false
	}
	*dst = addr.As16()
	return true
}

func calcChecksum(b []byte, initial uint32) uint16 {
	sum := initial
	n := len(b)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func calcIPv4HeaderChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i < 20; i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// EncodeToPacketBytes writes a raw wire-format packet (Ethernet + IP + UDP/TCP + DNS payload) directly
// into dst without any heap allocations.
func (dm *DNSMessage) EncodeToPacketBytes(dst []byte, overwritePort bool) ([]byte, error) {
	if len(dm.DNS.Payload) == 0 {
		return dst, errEmptyPayload
	}

	srcIPStr, srcPort, dstIPStr, dstPort := GetIPPort(dm)
	if srcPort < 0 || srcPort > math.MaxUint16 {
		return dst, errInvalidSrcPort
	}
	srcPortU16 := uint16(srcPort)

	if dstPort < 0 || dstPort > math.MaxUint16 {
		return dst, errInvalidDstPort
	}
	dstPortU16 := uint16(dstPort)

	isTCP := false
	switch dm.NetworkInfo.Protocol {
	case netutils.ProtoUDP, ProtoDoH, ProtoDoT, ProtoDoQ:
		isTCP = false
	case netutils.ProtoTCP:
		isTCP = true
	default:
		return dst, errProtocolNotImpl
	}

	if overwritePort {
		switch dm.DNS.Type {
		case DNSQuery:
			dstPortU16 = 53
		case DNSReply:
			srcPortU16 = 53
		}
	}

	dnsPayload := dm.DNS.Payload
	var tcpLenPrefix [2]byte
	if isTCP {
		binary.BigEndian.PutUint16(tcpLenPrefix[:], uint16(dm.DNS.Length))
	}

	isIPv4 := dm.NetworkInfo.Family == netutils.ProtoIPv4 || dm.NetworkInfo.Family == "INET"
	isIPv6 := dm.NetworkInfo.Family == netutils.ProtoIPv6 || dm.NetworkInfo.Family == "INET6"

	var srcIP4, dstIP4 [4]byte
	var srcIP6, dstIP6 [16]byte

	if !isIPv4 && !isIPv6 {
		qIP := dm.NetworkInfo.GetQueryIP()
		rIP := dm.NetworkInfo.GetResponseIP()
		switch {
		case dm.NetworkInfo.QueryIPLen == 16 || dm.NetworkInfo.ResponseIPLen == 16 ||
			(qIP != "-" && parseIPv6Bytes(qIP, &srcIP6)) ||
			(rIP != "-" && parseIPv6Bytes(rIP, &dstIP6)):
			isIPv6 = true
		case dm.NetworkInfo.QueryIPLen == 4 || dm.NetworkInfo.ResponseIPLen == 4 ||
			(qIP != "-" && parseIPv4Bytes(qIP, &srcIP4)) ||
			(rIP != "-" && parseIPv4Bytes(rIP, &dstIP4)) ||
			parseIPv4Bytes(srcIPStr, &srcIP4) || parseIPv4Bytes(dstIPStr, &dstIP4):
			isIPv4 = true
		default:
			return dst, errFamilyNotImpl
		}
	}

	if isIPv4 {
		if !parseIPv4Bytes(srcIPStr, &srcIP4) {
			addr, err := netip.ParseAddr(srcIPStr)
			if err != nil {
				return dst, errInvalidIPAddress
			}
			switch {
			case addr.Is4In6():
				srcIP4 = addr.Unmap().As4()
			case addr.Is4():
				srcIP4 = addr.As4()
			default:
				return dst, errInvalidIPAddress
			}
		}
		if !parseIPv4Bytes(dstIPStr, &dstIP4) {
			addr, err := netip.ParseAddr(dstIPStr)
			if err != nil {
				return dst, errInvalidIPAddress
			}
			switch {
			case addr.Is4In6():
				dstIP4 = addr.Unmap().As4()
			case addr.Is4():
				dstIP4 = addr.As4()
			default:
				return dst, errInvalidIPAddress
			}
		}
	} else {
		if !parseIPv6Bytes(srcIPStr, &srcIP6) {
			return dst, errInvalidIPAddress
		}
		if !parseIPv6Bytes(dstIPStr, &dstIP6) {
			return dst, errInvalidIPAddress
		}
	}

	// Calculate lengths
	transportPayloadLen := len(dnsPayload)
	if isTCP {
		transportPayloadLen += 2 // 2-byte length prefix
	}

	transportHeaderLen := 8
	if isTCP {
		transportHeaderLen = 20
	}
	transportTotalLen := transportHeaderLen + transportPayloadLen

	ipHeaderLen := 20
	if isIPv6 {
		ipHeaderLen = 40
	}
	totalPacketLen := 14 + ipHeaderLen + transportTotalLen

	// Grow dst slice
	startIdx := len(dst)
	if cap(dst)-startIdx < totalPacketLen {
		newDst := make([]byte, startIdx+totalPacketLen)
		copy(newDst, dst)
		dst = newDst
	} else {
		dst = dst[:startIdx+totalPacketLen]
	}
	pkt := dst[startIdx:]

	// 1. Ethernet Header (14 bytes)
	// DstMAC (0..5) = 0, SrcMAC (6..11) = 0
	for i := 0; i < 12; i++ {
		pkt[i] = 0
	}
	if isIPv4 {
		pkt[12] = 0x08
		pkt[13] = 0x00 // EtherType IPv4
	} else {
		pkt[12] = 0x86
		pkt[13] = 0xDD // EtherType IPv6
	}

	// 2. IP Header
	ipOffset := 14
	transportOffset := ipOffset + ipHeaderLen

	protoNum := byte(17) // UDP
	if isTCP {
		protoNum = 6 // TCP
	}

	if isIPv4 {
		pkt[ipOffset+0] = 0x45 // Version 4, IHL 5
		pkt[ipOffset+1] = 0x00 // DSCP / ECN
		binary.BigEndian.PutUint16(pkt[ipOffset+2:], uint16(20+transportTotalLen))
		pkt[ipOffset+4] = 0x00
		pkt[ipOffset+5] = 0x00 // ID
		pkt[ipOffset+6] = 0x00
		pkt[ipOffset+7] = 0x00 // Flags / Frag
		pkt[ipOffset+8] = 64   // TTL
		pkt[ipOffset+9] = protoNum
		pkt[ipOffset+10] = 0x00
		pkt[ipOffset+11] = 0x00 // Checksum placeholder
		copy(pkt[ipOffset+12:ipOffset+16], srcIP4[:])
		copy(pkt[ipOffset+16:ipOffset+20], dstIP4[:])

		csum := calcIPv4HeaderChecksum(pkt[ipOffset : ipOffset+20])
		binary.BigEndian.PutUint16(pkt[ipOffset+10:], csum)
	} else {
		// IPv6 Header (40 bytes)
		pkt[ipOffset+0] = 0x60 // Version 6
		pkt[ipOffset+1] = 0x00
		pkt[ipOffset+2] = 0x00
		pkt[ipOffset+3] = 0x00
		binary.BigEndian.PutUint16(pkt[ipOffset+4:], uint16(transportTotalLen))
		pkt[ipOffset+6] = protoNum // Next Header
		pkt[ipOffset+7] = 64       // Hop Limit
		copy(pkt[ipOffset+8:ipOffset+24], srcIP6[:])
		copy(pkt[ipOffset+24:ipOffset+40], dstIP6[:])
	}

	// 3. Transport Header & Payload
	if !isTCP {
		// UDP Header (8 bytes)
		binary.BigEndian.PutUint16(pkt[transportOffset+0:], srcPortU16)
		binary.BigEndian.PutUint16(pkt[transportOffset+2:], dstPortU16)
		binary.BigEndian.PutUint16(pkt[transportOffset+4:], uint16(transportTotalLen))
		pkt[transportOffset+6] = 0x00
		pkt[transportOffset+7] = 0x00 // Checksum placeholder

		copy(pkt[transportOffset+8:], dnsPayload)

		// Pseudo-header checksum
		var pSum uint32
		if isIPv4 {
			pSum = uint32(srcIP4[0])<<8 | uint32(srcIP4[1])
			pSum += uint32(srcIP4[2])<<8 | uint32(srcIP4[3])
			pSum += uint32(dstIP4[0])<<8 | uint32(dstIP4[1])
			pSum += uint32(dstIP4[2])<<8 | uint32(dstIP4[3])
			pSum += uint32(17) // protocol
			pSum += uint32(transportTotalLen)
		} else {
			for i := 0; i < 16; i += 2 {
				pSum += uint32(srcIP6[i])<<8 | uint32(srcIP6[i+1])
				pSum += uint32(dstIP6[i])<<8 | uint32(dstIP6[i+1])
			}
			pSum += uint32(transportTotalLen)
			pSum += uint32(17)
		}
		csum := calcChecksum(pkt[transportOffset:transportOffset+transportTotalLen], pSum)
		if csum == 0 {
			csum = 0xffff
		}
		binary.BigEndian.PutUint16(pkt[transportOffset+6:], csum)
	} else {
		// TCP Header (20 bytes)
		binary.BigEndian.PutUint16(pkt[transportOffset+0:], srcPortU16)
		binary.BigEndian.PutUint16(pkt[transportOffset+2:], dstPortU16)
		binary.BigEndian.PutUint32(pkt[transportOffset+4:], 1) // Seq
		binary.BigEndian.PutUint32(pkt[transportOffset+8:], 1) // Ack
		pkt[transportOffset+12] = 0x50                         // Data Offset = 5 (20 bytes)
		pkt[transportOffset+13] = 0x18                         // PSH | ACK
		binary.BigEndian.PutUint16(pkt[transportOffset+14:], 65535)
		pkt[transportOffset+16] = 0x00
		pkt[transportOffset+17] = 0x00 // Checksum placeholder
		pkt[transportOffset+18] = 0x00
		pkt[transportOffset+19] = 0x00 // Urgent ptr

		pkt[transportOffset+20] = tcpLenPrefix[0]
		pkt[transportOffset+21] = tcpLenPrefix[1]
		copy(pkt[transportOffset+22:], dnsPayload)

		// Pseudo-header checksum
		var pSum uint32
		if isIPv4 {
			pSum = uint32(srcIP4[0])<<8 | uint32(srcIP4[1])
			pSum += uint32(srcIP4[2])<<8 | uint32(srcIP4[3])
			pSum += uint32(dstIP4[0])<<8 | uint32(dstIP4[1])
			pSum += uint32(dstIP4[2])<<8 | uint32(dstIP4[3])
			pSum += uint32(6) // protocol TCP
			pSum += uint32(transportTotalLen)
		} else {
			for i := 0; i < 16; i += 2 {
				pSum += uint32(srcIP6[i])<<8 | uint32(srcIP6[i+1])
				pSum += uint32(dstIP6[i])<<8 | uint32(dstIP6[i+1])
			}
			pSum += uint32(transportTotalLen)
			pSum += uint32(6)
		}
		csum := calcChecksum(pkt[transportOffset:transportOffset+transportTotalLen], pSum)
		binary.BigEndian.PutUint16(pkt[transportOffset+16:], csum)
	}

	return dst, nil
}

// ToPacketLayer maintains compatibility with gopacket layer representation
func (dm *DNSMessage) ToPacketLayer(overwritePort bool) ([]gopacket.SerializableLayer, error) {
	if len(dm.DNS.Payload) == 0 {
		return nil, errEmptyPayload
	}

	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip6 := &layers.IPv6{Version: 6}
	udp := &layers.UDP{}
	tcp := &layers.TCP{}

	srcIP, srcPort, dstIP, dstPort := GetIPPort(dm)
	if srcPort < 0 || srcPort > math.MaxUint16 {
		return nil, errInvalidSrcPort
	}
	if dstPort < 0 || dstPort > math.MaxUint16 {
		return nil, errInvalidDstPort
	}

	pkt := []gopacket.SerializableLayer{}

	family := dm.NetworkInfo.Family
	if family != netutils.ProtoIPv4 && family != netutils.ProtoIPv6 {
		qIP := dm.NetworkInfo.GetQueryIP()
		rIP := dm.NetworkInfo.GetResponseIP()
		switch {
		case family == "INET":
			family = netutils.ProtoIPv4
		case family == "INET6":
			family = netutils.ProtoIPv6
		case dm.NetworkInfo.QueryIPLen == 16 || dm.NetworkInfo.ResponseIPLen == 16 ||
			(qIP != "-" && net.ParseIP(qIP) != nil && net.ParseIP(qIP).To4() == nil) ||
			(rIP != "-" && net.ParseIP(rIP) != nil && net.ParseIP(rIP).To4() == nil):
			family = netutils.ProtoIPv6
			if srcIP == "0.0.0.0" {
				srcIP = "::"
			}
			if dstIP == "0.0.0.0" {
				dstIP = "::"
			}
		case dm.NetworkInfo.QueryIPLen == 4 || dm.NetworkInfo.ResponseIPLen == 4 ||
			(qIP != "-" && net.ParseIP(qIP).To4() != nil) ||
			(rIP != "-" && net.ParseIP(rIP).To4() != nil) ||
			net.ParseIP(srcIP).To4() != nil || net.ParseIP(dstIP).To4() != nil:
			family = netutils.ProtoIPv4
		}
	}

	switch family {
	case netutils.ProtoIPv4:
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4.SrcIP = net.ParseIP(srcIP)
		ip4.DstIP = net.ParseIP(dstIP)
	case netutils.ProtoIPv6:
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6.SrcIP = net.ParseIP(srcIP)
		ip6.DstIP = net.ParseIP(dstIP)
	default:
		return nil, errors.New("family (" + dm.NetworkInfo.Family + ") not yet implemented")
	}

	switch dm.NetworkInfo.Protocol {
	case netutils.ProtoUDP:
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)

		if dm.DNS.Type == DNSQuery && overwritePort {
			udp.DstPort = 53
		}
		if dm.DNS.Type == DNSReply && overwritePort {
			udp.SrcPort = 53
		}

		switch family {
		case netutils.ProtoIPv4:
			ip4.Protocol = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4)
		case netutils.ProtoIPv6:
			ip6.NextHeader = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6)
		}

	case netutils.ProtoTCP:
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.PSH = true
		tcp.Window = 65535

		if dm.DNS.Type == DNSQuery && overwritePort {
			tcp.DstPort = 53
		}
		if dm.DNS.Type == DNSReply && overwritePort {
			tcp.SrcPort = 53
		}

		dnsLengthField := make([]byte, 2)
		binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.DNS.Length))

		switch family {
		case netutils.ProtoIPv4:
			ip4.Protocol = layers.IPProtocolTCP
			tcp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip4)
		case netutils.ProtoIPv6:
			ip6.NextHeader = layers.IPProtocolTCP
			tcp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip6)
		}

	case ProtoDoH, ProtoDoT, ProtoDoQ:
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)

		if dm.DNS.Type == DNSQuery && overwritePort {
			udp.DstPort = 53
		}
		if dm.DNS.Type == DNSReply && overwritePort {
			udp.SrcPort = 53
		}

		switch family {
		case netutils.ProtoIPv4:
			ip4.Protocol = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4)
		case netutils.ProtoIPv6:
			ip6.NextHeader = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6)
		}

	default:
		return nil, errors.New("protocol " + dm.NetworkInfo.Protocol + " not yet implemented")
	}

	pkt = append(pkt, eth)
	return pkt, nil
}
