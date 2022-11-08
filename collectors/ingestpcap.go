package collectors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type IngestPcap struct {
	done         chan bool
	exit         chan bool
	loggers      []dnsutils.Worker
	config       *dnsutils.Config
	logger       *logger.Logger
	watcher      *fsnotify.Watcher
	dnsProcessor DnsProcessor
	dropQueries  bool
	dropReplies  bool
	dnsPort      int
	identity     string
	name         string
}

func NewIngestPcap(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *IngestPcap {
	logger.Info("[%s] pcap collector - enabled", name)
	s := &IngestPcap{
		done:    make(chan bool),
		exit:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
		name:    name,
	}
	s.ReadConfig()
	return s
}

func (c *IngestPcap) GetName() string { return c.name }

func (c *IngestPcap) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *IngestPcap) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *IngestPcap) ReadConfig() {
	c.identity = c.config.GetServerIdentity()
	c.dnsPort = c.config.Collectors.IngestPcap.DnsPort
	c.dropQueries = c.config.Collectors.IngestPcap.DropQueries
	c.dropReplies = c.config.Collectors.IngestPcap.DropReplies
}

func (c *IngestPcap) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] pcap collector - "+msg, v...)
}

func (c *IngestPcap) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] pcap collector - "+msg, v...)
}

func (c *IngestPcap) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *IngestPcap) Stop() {
	c.LogInfo("stopping...")

	// stop watching
	c.watcher.Close()

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *IngestPcap) ProcessPcap(filePath string) error {

	// open the file
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// it is a pcap file ?
	pcapHandler, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}
	c.LogInfo("reading file [%s]...", filePath)

	if pcapHandler.LinkType() != layers.LinkTypeEthernet {
		msg := fmt.Sprintf("Link type not supported: %s", pcapHandler.LinkType())
		c.LogInfo("pcap file [%s] ignored!", filePath)
		return errors.New(msg)
	}

	// decode packets
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	packets := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())
	for {
		packet, err := packets.NextPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			c.LogError("failed to read packet: %s", err)
			continue
		}

		// parse layers
		parser.DecodeLayers(packet.Data(), &decodedLayers)

		// prepare dns message
		dm := dnsutils.DnsMessage{}
		dm.Init()

		ignore_packet := false
		for _, layertyp := range decodedLayers {
			switch layertyp {
			case layers.LayerTypeIPv4:
				dm.NetworkInfo.Family = dnsutils.PROTO_IPV4
				dm.NetworkInfo.QueryIp = ip4.SrcIP.String()
				dm.NetworkInfo.ResponseIp = ip4.DstIP.String()

			case layers.LayerTypeIPv6:
				dm.NetworkInfo.QueryIp = ip6.SrcIP.String()
				dm.NetworkInfo.ResponseIp = ip6.DstIP.String()
				dm.NetworkInfo.Family = dnsutils.PROTO_IPV6

			case layers.LayerTypeUDP:
				// ignore packet if the port is not equal to 53
				if int(udp.SrcPort) != c.dnsPort && int(udp.DstPort) != c.dnsPort {
					ignore_packet = true
					continue
				}
				dm.NetworkInfo.QueryPort = fmt.Sprint(int(udp.SrcPort))
				dm.NetworkInfo.ResponsePort = fmt.Sprint(int(udp.DstPort))
				dm.DNS.Payload = udp.Payload
				dm.DNS.Length = len(udp.Payload)
				dm.NetworkInfo.Protocol = dnsutils.PROTO_UDP

			case layers.LayerTypeTCP:
				// ignore packet if the port is not equal to 53
				if int(udp.SrcPort) != c.dnsPort && int(udp.DstPort) != c.dnsPort {
					ignore_packet = true
				}

				// ignore SYN/ACK packet
				if !tcp.PSH {
					ignore_packet = true
					continue
				}

				dnsLengthField := binary.BigEndian.Uint16(tcp.Payload[0:2])
				if len(tcp.Payload) < int(dnsLengthField) {
					ignore_packet = true
					continue
				}

				dm.NetworkInfo.QueryPort = fmt.Sprint(int(tcp.SrcPort))
				dm.NetworkInfo.ResponsePort = fmt.Sprint(int(tcp.DstPort))
				dm.DNS.Payload = tcp.Payload[2:]
				dm.DNS.Length = len(tcp.Payload[2:])
				dm.NetworkInfo.Protocol = dnsutils.PROTO_TCP
			}
		}

		if !ignore_packet {
			dm.DnsTap.Identity = c.identity

			// set timestamp
			dm.DnsTap.TimeSec = packet.Metadata().Timestamp.Second()
			dm.DnsTap.TimeNsec = int(packet.Metadata().Timestamp.UnixNano())

			// just decode QR
			if len(dm.DNS.Payload) < 4 {
				continue
			}
			qr := binary.BigEndian.Uint16(dm.DNS.Payload[2:4]) >> 15

			// is query ?
			if int(qr) == 0 && !c.dropQueries {
				c.dnsProcessor.GetChannel() <- dm
			}

			// is reply
			if int(qr) == 1 && !c.dropReplies {
				c.dnsProcessor.GetChannel() <- dm
			}
		}

	}
	// remove it ?
	c.LogInfo("ingest [%s] terminated", filePath)
	if c.config.Collectors.IngestPcap.DeleteAfter {
		c.LogInfo("delete file [%s]", filePath)
		os.Remove(filePath)
	}

	return nil
}

func (c *IngestPcap) Run() {
	c.LogInfo("starting collector...")

	c.dnsProcessor = NewDnsProcessor(c.config, c.logger, c.name)
	c.dnsProcessor.cacheSupport = c.config.Collectors.LiveCapture.CacheSupport
	c.dnsProcessor.queryTimeout = c.config.Collectors.LiveCapture.QueryTimeout
	go c.dnsProcessor.Run(c.Loggers())

	// read folder content
	entries, err := os.ReadDir(c.config.Collectors.IngestPcap.WatchDir)
	if err != nil {
		c.LogError("unable to read folder: %s", err)
	}

	for _, entry := range entries {
		// ignore folder
		if entry.IsDir() {
			continue
		}

		// prepare filepath
		fn := filepath.Join(c.config.Collectors.IngestPcap.WatchDir, entry.Name())

		// process file with pcap extension
		if filepath.Ext(fn) == ".pcap" {
			go c.ProcessPcap(fn)
		}
	}

	// then watch for new one
	c.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	// register the folder to watch
	err = c.watcher.Add(c.config.Collectors.IngestPcap.WatchDir)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			select {
			case event, ok := <-c.watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					// process file with pcap extension only
					if filepath.Ext(event.Name) == ".pcap" {
						go c.ProcessPcap(event.Name)
					}
				}
			case err, ok := <-c.watcher.Errors:
				if !ok {
					return
				}
				c.LogError("error:", err)
			}
		}
	}()

	<-c.exit

	// stop dns processor
	c.dnsProcessor.Stop()

	c.LogInfo("run terminated")
	c.done <- true
}
