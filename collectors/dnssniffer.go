package collectors

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Convert a uint16 to host byte order (big endian)
func Htons(v uint16) int {
	return int((v << 8) | (v >> 8))
}

type DnsSniffer struct {
	done       chan bool
	exit       chan bool
	device     string
	filter     string
	identity   string
	generators []dnsutils.Worker
	config     *dnsutils.Config
	logger     *logger.Logger
}

func NewDnsSniffer(generators []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger) *DnsSniffer {
	logger.Info("collector dns sniffer - enabled")
	s := &DnsSniffer{
		done:       make(chan bool),
		exit:       make(chan bool),
		config:     config,
		generators: generators,
		logger:     logger,
	}
	s.ReadConfig()
	return s
}

func (c *DnsSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("collector dns sniffer - "+msg, v...)
}

func (c *DnsSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("collector dns sniffer - "+msg, v...)
}

func (c *DnsSniffer) Generators() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.generators {
		channels = append(channels, p.Channel())
	}
	return channels
}
func (c *DnsSniffer) ReadConfig() {
	c.device = c.config.Collectors.DnsSniffer.Device
	c.filter = c.config.Collectors.DnsSniffer.Filter
	c.identity = c.config.Collectors.DnsSniffer.Identity
}

func (c *DnsSniffer) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *DnsSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *DnsSniffer) Run() {
	dns_processor := processors.NewDnsProcessor(c.logger)
	go dns_processor.Run(c.Generators())

	sd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, Htons(syscall.ETH_P_ALL))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sd)

	// set nano timestamp
	err = syscall.SetsockoptInt(sd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1)
	if err != nil {
		panic(err)
	}

	go func() {
		buf := make([]byte, 65536)
		oob := make([]byte, 100)
		for {
			//flags, from
			bufN, oobn, _, _, err := syscall.Recvmsg(sd, buf, oob, 0)
			if err != nil {
				panic(err)
			}
			if bufN == 0 {
				panic("buf empty")
			}
			if bufN > len(buf) {
				panic("buf overflow")
			}
			if oobn == 0 {
				panic("oob missing")
			}

			scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				panic(err)
			}
			if len(scms) != 1 {
				continue
			}
			scm := scms[0]
			if scm.Header.Type != syscall.SCM_TIMESTAMPNS {
				panic("scm timestampns missing")
			}
			tsec := binary.LittleEndian.Uint32(scm.Data[:4])
			nsec := binary.LittleEndian.Uint32(scm.Data[8:12])

			var eth layers.Ethernet
			var ip4 layers.IPv4
			var ip6 layers.IPv6
			var tcp layers.TCP
			var udp layers.UDP
			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
			decodedLayers := make([]gopacket.LayerType, 0, 10)

			// copy packet data from buffer
			pkt := make([]byte, bufN)
			copy(pkt, buf[:bufN])

			// decode-it
			parser.DecodeLayers(pkt, &decodedLayers)
			dm := dnsutils.DnsMessage{}
			dm.Init()

			dnspacket := false
			for _, layertyp := range decodedLayers {
				switch layertyp {
				case layers.LayerTypeIPv4:
					if ip4.FragOffset != 0 || (ip4.Flags&layers.IPv4MoreFragments) != 0 {
						continue // Ignore fragmented packets, not yet supported.
					}
					dm.Family = "INET"
					dm.QueryIp = ip4.SrcIP.String()
					dm.ResponseIp = ip4.DstIP.String()
				case layers.LayerTypeIPv6:
					if ip6.NextHeader.LayerType() == layers.LayerTypeIPv6Fragment {
						continue // Ignore fragmented packets, not yet supported.
					}
					dm.QueryIp = ip6.SrcIP.String()
					dm.ResponseIp = ip6.DstIP.String()
					dm.Family = "INET6"
				case layers.LayerTypeUDP:
					dm.QueryPort = fmt.Sprint(int(udp.SrcPort))
					dm.ResponsePort = fmt.Sprint(int(udp.DstPort))
					dm.Payload = udp.Payload
					dm.Length = len(udp.Payload)
					dm.Protocol = "UDP"

					if dm.QueryPort != "53" && dm.ResponsePort != "53" {
						continue
					}
					dnspacket = true
				case layers.LayerTypeTCP:
					dm.QueryPort = fmt.Sprint(int(tcp.SrcPort))
					dm.ResponsePort = fmt.Sprint(int(tcp.DstPort))
					dm.Payload = tcp.Payload
					dm.Length = len(tcp.Payload)
					dm.Protocol = "TCP"

					if dm.QueryPort != "53" && dm.ResponsePort != "53" {
						continue
					}
					dnspacket = true
				}
			}

			if dnspacket {
				// set identity
				dm.Identity = c.identity

				// set timestamp
				dm.TimeSec = int(tsec)
				dm.TimeNsec = int(nsec)

				dns_processor.GetChannel() <- dm
			}
		}
	}()

	<-c.exit

	// stop dns processor
	dns_processor.Stop()

	c.LogInfo("run terminated")
	c.done <- true
}
