package dnsutils

import (
	"encoding/binary"
	"errors"
	"math"
	"net"

	"github.com/dmachard/go-netutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (dm *DNSMessage) ToPacketLayer() ([]gopacket.SerializableLayer, error) {
	if len(dm.DNS.Payload) == 0 {
		return nil, errors.New("payload is empty")
	}

	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip6 := &layers.IPv6{Version: 6}
	udp := &layers.UDP{}
	tcp := &layers.TCP{}

	// prepare ip
	srcIP, srcPort, dstIP, dstPort := GetIPPort(dm)
	if srcPort < 0 || srcPort > math.MaxUint16 {
		return nil, errors.New("invalid source port value")
	}
	if dstPort < 0 || dstPort > math.MaxUint16 {
		return nil, errors.New("invalid destination port value")
	}

	// packet layer array
	pkt := []gopacket.SerializableLayer{}

	// set source and destination IP
	switch dm.NetworkInfo.Family {
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

	// set transport
	switch dm.NetworkInfo.Protocol {

	// DNS over UDP
	case netutils.ProtoUDP:
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)

		// update iplayer
		switch dm.NetworkInfo.Family {
		case netutils.ProtoIPv4:
			ip4.Protocol = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4)
		case netutils.ProtoIPv6:
			ip6.NextHeader = layers.IPProtocolUDP
			udp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6)
		}

	// DNS over TCP
	case netutils.ProtoTCP:
		tcp.SrcPort = layers.TCPPort(srcPort)
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.PSH = true
		tcp.Window = 65535

		// dns length
		dnsLengthField := make([]byte, 2)
		binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.DNS.Length))

		// update iplayer
		switch dm.NetworkInfo.Family {
		case netutils.ProtoIPv4:
			ip4.Protocol = layers.IPProtocolTCP
			tcp.SetNetworkLayerForChecksum(ip4)
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip4)
		case netutils.ProtoIPv6:
			ip6.NextHeader = layers.IPProtocolTCP
			tcp.SetNetworkLayerForChecksum(ip6)
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip6)
		}

	// DNS over HTTPS and DNS over TLS
	// These protocols are translated to DNS over UDP
	case ProtoDoH, ProtoDoT:
		udp.SrcPort = layers.UDPPort(srcPort)
		udp.DstPort = layers.UDPPort(dstPort)

		// update iplayer
		switch dm.NetworkInfo.Family {
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
