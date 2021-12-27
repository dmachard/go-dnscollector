package loggers

import (
	"log"
	"net"
	"os"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPcapfileWrite(t *testing.T) {
	// create a temp file
	f, err := os.CreateTemp("", "temp_pcapfile")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name()) // clean up

	// config
	config := dnsutils.GetFakeConfig()
	config.Loggers.PcapFile.FilePath = f.Name()

	// init generator in testing mode
	g := NewPcapFile(config, logger.New(false))

	// init fake dm
	dm := dnsutils.GetFakeDnsMessage()

	// fake network packet
	pkt := []gopacket.SerializableLayer{}

	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	eth.EthernetType = layers.EthernetTypeIPv4

	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip4.SrcIP = net.ParseIP("127.0.0.1")
	ip4.DstIP = net.ParseIP("127.0.0.1")
	ip4.Protocol = layers.IPProtocolUDP

	udp := &layers.UDP{}
	udp.SrcPort = layers.UDPPort(1000)
	udp.DstPort = layers.UDPPort(53)
	udp.SetNetworkLayerForChecksum(ip4)

	pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4, eth)

	// write fake dns message and network packet
	g.Write(dm, pkt)

	// read temp file and check content
	data := make([]byte, 100)
	count, err := f.Read(data)
	if err != nil {
		log.Fatal(err)
	}

	if count == 0 {
		t.Errorf("no data in pcap file")
	}
}
