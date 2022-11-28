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
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func IsValidMode(mode string) bool {
	switch mode {
	case
		dnsutils.MODE_PCAP,
		dnsutils.MODE_DNSTAP:
		return true
	}
	return false
}

type FileIngestor struct {
	done            chan bool
	exit            chan bool
	loggers         []dnsutils.Worker
	config          *dnsutils.Config
	logger          *logger.Logger
	watcher         *fsnotify.Watcher
	dnsProcessor    DnsProcessor
	dnstapProcessor DnstapProcessor
	dropQueries     bool
	dropReplies     bool
	dnsPort         int
	identity        string
	name            string
}

func NewFileIngestor(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *FileIngestor {
	logger.Info("[%s] pcap collector - enabled", name)
	s := &FileIngestor{
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

func (c *FileIngestor) GetName() string { return c.name }

func (c *FileIngestor) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *FileIngestor) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *FileIngestor) ReadConfig() {
	if !IsValidMode(c.config.Collectors.FileIngestor.WatchMode) {
		c.logger.Fatal("collector file ingestor - invalid mode: ", c.config.Collectors.FileIngestor.WatchMode)
	}

	c.identity = c.config.GetServerIdentity()
	c.dnsPort = c.config.Collectors.FileIngestor.PcapDnsPort
	c.dropQueries = c.config.Collectors.FileIngestor.DropQueries
	c.dropReplies = c.config.Collectors.FileIngestor.DropReplies

	c.LogInfo("watching directory to find %s files", c.config.Collectors.FileIngestor.WatchMode)
}

func (c *FileIngestor) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] pcap collector - "+msg, v...)
}

func (c *FileIngestor) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] pcap collector - "+msg, v...)
}

func (c *FileIngestor) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *FileIngestor) Stop() {
	c.LogInfo("stopping...")

	// stop watching
	c.watcher.Close()

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *FileIngestor) ProcessPcap(filePath string) error {

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
	c.LogInfo("ingest pcap [%s] terminated", filePath)
	if c.config.Collectors.FileIngestor.DeleteAfter {
		c.LogInfo("delete file [%s]", filePath)
		os.Remove(filePath)
	}

	return nil
}

func (c *FileIngestor) ProcessDnstap(filePath string) error {
	// open the file
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	dnstapDecoder, err := framestream.NewDecoder(f, &framestream.DecoderOptions{
		ContentType:   []byte("protobuf:dnstap.Dnstap"),
		Bidirectional: false,
	})

	if err != nil {
		return fmt.Errorf("failed to create framestream Decoder: %w", err)
	}

	for {
		buf, err := dnstapDecoder.Decode()
		if errors.Is(err, io.EOF) {
			break
		}

		newbuf := make([]byte, len(buf))
		copy(newbuf, buf)

		c.dnstapProcessor.GetChannel() <- newbuf
	}

	// remove it ?
	c.LogInfo("ingest dnstap [%s] terminated", filePath)
	if c.config.Collectors.FileIngestor.DeleteAfter {
		c.LogInfo("delete file [%s]", filePath)
		os.Remove(filePath)
	}

	return nil
}

func (c *FileIngestor) Run() {
	c.LogInfo("starting collector...")

	c.dnsProcessor = NewDnsProcessor(c.config, c.logger, c.name)
	go c.dnsProcessor.Run(c.Loggers())

	// start dnstap subprocessor
	c.dnstapProcessor = NewDnstapProcessor(c.config, c.logger, c.name)
	go c.dnstapProcessor.Run(c.Loggers())

	// read folder content
	entries, err := os.ReadDir(c.config.Collectors.FileIngestor.WatchDir)
	if err != nil {
		c.LogError("unable to read folder: %s", err)
	}

	for _, entry := range entries {
		// ignore folder
		if entry.IsDir() {
			continue
		}

		// prepare filepath
		fn := filepath.Join(c.config.Collectors.FileIngestor.WatchDir, entry.Name())

		// process file with pcap extension
		if filepath.Ext(fn) == ".pcap" {
			go c.ProcessPcap(fn)
		}

		// processs dnstap
		if filepath.Ext(fn) == ".fstrm" {
			go c.ProcessDnstap(fn)
		}
	}

	// then watch for new one
	c.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	// register the folder to watch
	err = c.watcher.Add(c.config.Collectors.FileIngestor.WatchDir)
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

					switch c.config.Collectors.FileIngestor.WatchMode {
					case dnsutils.MODE_PCAP:
						// process file with pcap extension only
						if filepath.Ext(event.Name) == ".pcap" {
							go c.ProcessPcap(event.Name)
						}
					case dnsutils.MODE_DNSTAP:
						// processs dnstap
						if filepath.Ext(event.Name) == ".fstrm" {
							go c.ProcessDnstap(event.Name)
						}
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
	c.dnstapProcessor.Stop()

	c.LogInfo("run terminated")
	c.done <- true
}
