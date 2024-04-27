package netutils

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// DefragPacket is a struct that holds DNS data
type DNSPacket struct {
	// DNS payload
	Payload []byte
	// IP layer
	IPLayer gopacket.Flow
	// Transport layer
	TransportLayer gopacket.Flow
	// Timestamp
	Timestamp time.Time
	// IP Defragmented
	IPDefragmented bool
	// TCP reassembly
	TCPReassembled bool
}

func UDPProcessor(udpInput chan gopacket.Packet, dnsOutput chan DNSPacket, portFilter int) {
	for packet := range udpInput {
		p := packet.TransportLayer().(*layers.UDP)

		if portFilter > 0 {
			if int(p.SrcPort) != portFilter && int(p.DstPort) != portFilter {
				continue
			}
		}

		dnsOutput <- DNSPacket{
			Payload:        p.Payload,
			IPLayer:        packet.NetworkLayer().NetworkFlow(),
			TransportLayer: p.TransportFlow(),
			Timestamp:      packet.Metadata().Timestamp,
			TCPReassembled: false,
			IPDefragmented: packet.Metadata().Truncated,
		}
	}
}

func TCPAssembler(tcpInput chan gopacket.Packet, dnsOutput chan DNSPacket, portFilter int) {
	streamFactory := &DNSStreamFactory{Reassembled: dnsOutput}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	ticker := time.NewTicker(time.Minute * 1)

	for {
		select {
		case packet, more := <-tcpInput:
			if !more {
				goto FLUSHALL
			}
			p := packet.TransportLayer().(*layers.TCP)

			// ip fragments should not happened with tcp ...
			if packet.Metadata().Truncated {
				streamFactory.IPDefragmented = packet.Metadata().Truncated
			}

			// ignore packet ?
			if portFilter > 0 {
				if int(p.SrcPort) != portFilter && int(p.DstPort) != portFilter {
					continue
				}
			}

			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				packet.TransportLayer().(*layers.TCP),
				packet.Metadata().Timestamp,
			)
		case <-ticker.C:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
FLUSHALL:
	assembler.FlushAll()
}

func IPDefragger(ipInput chan gopacket.Packet, udpOutput chan gopacket.Packet, tcpOutput chan gopacket.Packet, port int) {
	defragger := NewIPDefragmenter()
	for fragment := range ipInput {
		reassembled, err := defragger.DefragIP(fragment)
		if err != nil {
			break
		}
		if reassembled == nil {
			continue
		}

		if reassembled.TransportLayer() != nil && reassembled.TransportLayer().LayerType() == layers.LayerTypeUDP {
			// ignore packet regarding udp port
			pkt := reassembled.TransportLayer().(*layers.UDP)
			if pkt.DstPort != layers.UDPPort(port) && pkt.SrcPort != layers.UDPPort(port) {
				continue
			}
			// valid reassembled packet
			udpOutput <- reassembled
		}
		if reassembled.TransportLayer() != nil && reassembled.TransportLayer().LayerType() == layers.LayerTypeTCP {
			// ignore packet regarding udp port
			pkt := reassembled.TransportLayer().(*layers.TCP)
			if pkt.DstPort != layers.TCPPort(port) && pkt.SrcPort != layers.TCPPort(port) {
				continue
			}
			// valid reassembled packet
			tcpOutput <- reassembled
		}
	}
}
