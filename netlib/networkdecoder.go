package netlib

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NetDecoder struct{}

const (
	IPv4ProtocolTCP      = layers.IPProtocolTCP
	IPv4ProtocolUDP      = layers.IPProtocolUDP
	IPv6ProtocolTCP      = layers.IPProtocolTCP
	IPv6ProtocolUDP      = layers.IPProtocolUDP
	IPv6ProtocolFragment = layers.IPProtocolIPv6Fragment
)

func (d *NetDecoder) Decode(data []byte, p gopacket.PacketBuilder) error {
	// Decode the Ethernet layer
	ethernetLayer := &layers.Ethernet{}
	if err := ethernetLayer.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(ethernetLayer)
	p.SetLinkLayer(ethernetLayer)

	// Check the EtherType of the Ethernet layer to determine the next layer
	switch ethernetLayer.EthernetType {
	case layers.EthernetTypeIPv4:
		return d.decodeIPv4(ethernetLayer.Payload, p)
	case layers.EthernetTypeIPv6:
		return d.decodeIPv6(ethernetLayer.Payload, p)
	}

	return nil
}

func (d *NetDecoder) decodeIPv4(data []byte, p gopacket.PacketBuilder) error {
	// Decode the IPv4 layer
	ipv4Layer := &layers.IPv4{}
	if err := ipv4Layer.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(ipv4Layer)
	p.SetNetworkLayer(ipv4Layer)

	// Check the Protocol of the IPv4 layer to determine the next layer
	switch ipv4Layer.Protocol {
	case IPv4ProtocolTCP:
		return d.decodeTCP(ipv4Layer.Payload, p)
	case IPv4ProtocolUDP:
		return d.decodeUDP(ipv4Layer.Payload, p)
	}

	return nil
}

func (d *NetDecoder) decodeIPv6(data []byte, p gopacket.PacketBuilder) error {

	ipv6Layer := &layers.IPv6{}
	if err := ipv6Layer.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(ipv6Layer)
	p.SetNetworkLayer(ipv6Layer)

	// Check the NextHeader of the IPv6 layer to determine the next layer
	switch ipv6Layer.NextHeader {
	case IPv6ProtocolTCP:
		return d.decodeTCP(ipv6Layer.Payload, p)
	case IPv6ProtocolUDP:
		return d.decodeUDP(ipv6Layer.Payload, p)
	case IPv6ProtocolFragment:
		return d.decodeIPv6Fragment(ipv6Layer.Payload, p)
	}
	return nil
}

func (d *NetDecoder) decodeIPv6Fragment(data []byte, p gopacket.PacketBuilder) error {
	// Create a new packet from the byte slice
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv6Fragment, gopacket.Default)

	ipv6FragLayer := packet.Layer(layers.LayerTypeIPv6Fragment)
	if ipv6FragLayer == nil {
		return fmt.Errorf("no ipv6 fragment layer")
	}

	p.AddLayer(ipv6FragLayer)

	ipv6Frag := ipv6FragLayer.(*layers.IPv6Fragment)

	// This is the last fragment, so we can decode the payload
	switch ipv6Frag.NextHeader {
	case layers.IPProtocolTCP:
		return d.decodeTCP(ipv6FragLayer.LayerPayload(), p)
	case layers.IPProtocolUDP:
		return d.decodeUDP(ipv6FragLayer.LayerPayload(), p)
	}
	return nil
}

func (d *NetDecoder) decodeTCP(data []byte, p gopacket.PacketBuilder) error {
	// Decode the TCP layer
	tcpLayer := &layers.TCP{}
	if err := tcpLayer.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(tcpLayer)
	p.SetTransportLayer(tcpLayer)

	return nil
}

func (d *NetDecoder) decodeUDP(data []byte, p gopacket.PacketBuilder) error {
	// Decode the UDP layer
	udpLayer := &layers.UDP{}
	if err := udpLayer.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(udpLayer)
	p.SetTransportLayer(udpLayer)

	return nil
}
