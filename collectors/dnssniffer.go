package collectors

import (
	"io"
	"log"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
	// Open device
	handle, err := pcap.OpenLive(c.device, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// filter
	err = handle.SetBPFFilter(c.filter)
	if err != nil {
		c.logger.Fatal(err)
	}

	dns_processor := processors.NewDnsProcessor(c.logger)
	go dns_processor.Run(c.Generators())

	go func() {
		var eth layers.Ethernet
		var ip4 layers.IPv4
		var ip6 layers.IPv6
		var tcp layers.TCP
		var udp layers.UDP
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
		decodedLayers := make([]gopacket.LayerType, 0, 10)
		for {
			data, capinfo, err := handle.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}
			parser.DecodeLayers(data, &decodedLayers)

			dm := dnsutils.DnsMessage{}
			dm.Init()

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
					dm.QueryPort = udp.SrcPort.String()
					dm.ResponsePort = udp.DstPort.String()
					dm.Payload = udp.Payload
					dm.Length = len(udp.Payload)
					dm.Protocol = "UDP"
				case layers.LayerTypeTCP:
					dm.QueryPort = tcp.SrcPort.String()
					dm.ResponsePort = tcp.DstPort.String()
					dm.Payload = tcp.Payload
					dm.Length = len(tcp.Payload)
					dm.Protocol = "TCP"
				}
			}

			// set identity
			dm.Identity = c.identity

			// set timestamp
			ts := capinfo.Timestamp.UnixNano()
			dm.TimeSec = int(ts / 1e9)
			dm.TimeNsec = int(ts) - dm.TimeSec*1e9

			dns_processor.GetChannel() <- dm
		}
	}()

	<-c.exit

	// stop dns processor
	dns_processor.Stop()

	c.LogInfo("run terminated")
	c.done <- true
}
