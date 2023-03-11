package netlib

import (
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func Test_IpDefrag(t *testing.T) {
	tests := []struct {
		name      string
		pcapFile  string
		nbPackets int
	}{
		{
			name:      "DNS UDP with IPv4 Fragmented",
			pcapFile:  "./../testsdata/pcap/dnsdump_ip4_fragmented+udp.pcap",
			nbPackets: 2,
		},

		{
			name:      "DNS UDP with IPv6 Fragmented",
			pcapFile:  "./../testsdata/pcap/dnsdump_ip6_fragmented+udp.pcap",
			nbPackets: 2,
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

			fragIp4Chan := make(chan gopacket.Packet)
			fragIp6Chan := make(chan gopacket.Packet)
			outputChan := make(chan gopacket.Packet, 2)

			// defrag ipv4
			go IpDefragger(fragIp4Chan, outputChan, outputChan)
			// defrag ipv6
			go IpDefragger(fragIp6Chan, outputChan, outputChan)

			packetSource := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())
			packetSource.DecodeOptions.Lazy = true

			nbPackets := 0
			timeout := time.After(1 * time.Second)
			go func() {

				for {
					select {
					case <-outputChan:
						nbPackets++
					case <-timeout:
						goto STOP
					}
				}
			STOP:
				done <- true
			}()

			for {
				packet, err := packetSource.NextPacket()
				if err != nil {
					break
				}

				// ipv4 fragmented packet ?
				if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
					ip4 := packet.NetworkLayer().(*layers.IPv4)
					if ip4.Flags&layers.IPv4MoreFragments == 1 || ip4.FragOffset > 0 {
						fragIp4Chan <- packet
					} else {
						outputChan <- packet
					}
				}

				if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
					v6frag := packet.Layer(layers.LayerTypeIPv6Fragment)
					if v6frag != nil {
						fragIp6Chan <- packet
					} else {
						outputChan <- packet
					}
				}

			}

			<-done

			if nbPackets != tc.nbPackets {
				t.Errorf("bad number of packets, wants: %d, got: %d", tc.nbPackets, nbPackets)
			}
		})
	}
}
