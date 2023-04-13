package loggers

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Test_LogFileText(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    dnsutils.MODE_TEXT,
			pattern: "0b dns.collector A",
		},
		{
			mode:    dnsutils.MODE_JSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    dnsutils.MODE_FLATJSON,
			pattern: "\"dns.qname\":\"dns.collector\"",
		},
	}

	for i, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {

			// create a temp file
			f, err := os.CreateTemp("", fmt.Sprintf("temp_logfile%d", i))
			if err != nil {
				log.Fatal(err)
			}
			defer os.Remove(f.Name()) // clean up

			// config
			config := dnsutils.GetFakeConfig()
			config.Loggers.LogFile.FilePath = f.Name()
			config.Loggers.LogFile.Mode = tc.mode
			config.Loggers.LogFile.FlushInterval = 0

			// init generator in testing mode
			g := NewLogFile(config, logger.New(false), "test")

			// start the logger
			go g.Run()

			// send fake dns message to logger
			dm := dnsutils.GetFakeDnsMessage()
			dm.DnsTap.Identity = "test_id"
			g.channel <- dm

			time.Sleep(time.Second)
			g.Stop()

			// read temp file and check content
			data := make([]byte, 1024)
			count, err := f.Read(data)
			if err != nil {
				log.Fatal(err)
			}

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(data[:count])) {
				t.Errorf("loki test error want %s, got: %s", tc.pattern, string(data[:count]))
			}
		})
	}
}

func Test_LogFileWrite_PcapMode(t *testing.T) {
	// create a temp file
	f, err := os.CreateTemp("", "temp_pcapfile")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name()) // clean up

	// config
	config := dnsutils.GetFakeConfig()
	config.Loggers.LogFile.FilePath = f.Name()
	config.Loggers.LogFile.Mode = dnsutils.MODE_PCAP

	// init generator in testing mode
	g := NewLogFile(config, logger.New(false), "test")

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
	g.WriteToPcap(dm, pkt)

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
