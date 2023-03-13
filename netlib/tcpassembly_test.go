package netlib

import (
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
)

func Test_TcpAssembly(t *testing.T) {
	tests := []struct {
		name      string
		pcapFile  string
		nbPackets int
	}{
		{
			name:      "DNS UDP",
			pcapFile:  "./../testsdata/pcap/dnsdump_udp.pcap",
			nbPackets: 33,
		},

		{
			name:      "DNS TCP",
			pcapFile:  "./../testsdata/pcap/dnsdump_tcp.pcap",
			nbPackets: 10,
		},

		{
			name:      "DNS UDP+TCP",
			pcapFile:  "./../testsdata/pcap/dnsdump_udp+tcp.pcap",
			nbPackets: 4,
		},

		{
			name:      "DNS UDP Truncated + TCP fragmented",
			pcapFile:  "./../testsdata/pcap/dnsdump_udp_truncated+tcp_fragmented.pcap",
			nbPackets: 4,
		},

		{
			name:      "DNS TCP FASTOPEN",
			pcapFile:  "./../testsdata/pcap/dnsdump_tcp_fastopen.pcap",
			nbPackets: 8,
		},
	}

	done := make(chan bool)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.pcapFile)
			if err != nil {
				t.Errorf("unable to open file: %s", err)
				return
			}
			defer f.Close()

			pcapHandler, err := pcapgo.NewReader(f)
			if err != nil {
				t.Errorf("unable to open pcap file: %s", err)
				return
			}

			reassembleChan := make(chan DnsPacket)
			streamFactory := &DnsStreamFactory{Reassembled: reassembleChan}
			streamPool := tcpassembly.NewStreamPool(streamFactory)
			assembler := tcpassembly.NewAssembler(streamPool)

			packetSource := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())
			packetSource.DecodeOptions.Lazy = true

			nbPackets := 0
			go func() {
				for {
					dnsPacket := <-reassembleChan
					if len(dnsPacket.Payload) == 0 {
						break
					}
					// count it
					nbPackets++
				}
				done <- true
			}()

			for {
				packet, err := packetSource.NextPacket()
				if err != nil {
					break
				}

				if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
					p := packet.TransportLayer().(*layers.UDP)
					reassembleChan <- DnsPacket{
						Payload:        p.Payload,
						IpLayer:        packet.NetworkLayer().NetworkFlow(),
						TransportLayer: p.TransportFlow(),
						Timestamp:      packet.Metadata().Timestamp,
					}
				}
				if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
					assembler.AssembleWithTimestamp(
						packet.NetworkLayer().NetworkFlow(),
						packet.TransportLayer().(*layers.TCP),
						packet.Metadata().Timestamp,
					)
				}
			}
			// send empty packet to stop the goroutine
			reassembleChan <- DnsPacket{}

			<-done
			if nbPackets != tc.nbPackets {
				t.Errorf("bad number of packets, wants: %d, got: %d", tc.nbPackets, nbPackets)
			}
		})
	}
}
