package netlib

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func createIPv6FragmentPacketWithNilLayer() gopacket.Packet {
	// IPv6 layer
	ipLayer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Fragment, // Next header is Fragmentation Header
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}

	// Create a packet with nil IPv6Fragment layer
	builder := gopacket.NewSerializeBuffer()
	ipLayer.SerializeTo(builder, gopacket.SerializeOptions{})
	// Set the IPv6 layer manually
	packet := gopacket.NewPacket(builder.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
	// Remove IPv6Fragment layer
	packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment).Payload = nil

	return packet
}

func TestIpDefrag_WithNilIPv6Fragment(t *testing.T) {
	defragger := NewIPDefragmenter()

	// Create an IPv6 packet with nil IPv6Fragment layer
	packet := createIPv6FragmentPacketWithNilLayer()

	// This packet has a nil IPv6Fragment layer, which should trigger an error
	_, err := defragger.DefragIP(packet)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}
