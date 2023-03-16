package collectors

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-logger"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var waitFor = 10 * time.Second

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
	watcherTimers   map[string]*time.Timer
	dnsProcessor    DnsProcessor
	dnstapProcessor DnstapProcessor
	filterDnsPort   int
	identity        string
	name            string
	mu              sync.Mutex
}

func NewFileIngestor(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *FileIngestor {
	logger.Info("[%s] file ingestor - enabled", name)
	s := &FileIngestor{
		done:          make(chan bool),
		exit:          make(chan bool),
		config:        config,
		loggers:       loggers,
		logger:        logger,
		name:          name,
		watcherTimers: make(map[string]*time.Timer),
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
	c.filterDnsPort = c.config.Collectors.FileIngestor.PcapDnsPort

	c.LogInfo("watching directory [%s] to find [%s] files",
		c.config.Collectors.FileIngestor.WatchDir,
		c.config.Collectors.FileIngestor.WatchMode)
}

func (c *FileIngestor) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] file ingestor - "+msg, v...)
}

func (c *FileIngestor) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] file ingestor - "+msg, v...)
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

func (c *FileIngestor) ProcessFile(filePath string) {
	switch c.config.Collectors.FileIngestor.WatchMode {
	case dnsutils.MODE_PCAP:
		// process file with pcap extension only
		if filepath.Ext(filePath) == ".pcap" || filepath.Ext(filePath) == ".pcap.gz" {
			c.LogInfo("file ready to process %s", filePath)
			go c.ProcessPcap(filePath)
		}
	case dnsutils.MODE_DNSTAP:
		// processs dnstap
		if filepath.Ext(filePath) == ".fstrm" {
			c.LogInfo("file ready to process %s", filePath)
			go c.ProcessDnstap(filePath)
		}
	}
}

func (c *FileIngestor) ProcessPcap(filePath string) {
	// open the file
	f, err := os.Open(filePath)
	if err != nil {
		c.LogError("unable to read file: %s", err)
		return
	}
	defer f.Close()

	// it is a pcap file ?
	pcapHandler, err := pcapgo.NewReader(f)
	if err != nil {
		c.LogError("unable to read pcap file: %s", err)
		return
	}

	fileName := filepath.Base(filePath)
	c.LogInfo("processing pcap file [%s]...", fileName)

	if pcapHandler.LinkType() != layers.LinkTypeEthernet {
		c.LogError("pcap file [%s] ignored: %s", filePath, pcapHandler.LinkType())
		return
	}

	dnsChan := make(chan netlib.DnsPacket)
	udpChan := make(chan gopacket.Packet)
	tcpChan := make(chan gopacket.Packet)
	fragIp4Chan := make(chan gopacket.Packet)
	fragIp6Chan := make(chan gopacket.Packet)

	packetSource := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.NoCopy = true

	// defrag ipv4
	go netlib.IpDefragger(fragIp4Chan, udpChan, tcpChan)
	// defrag ipv6
	go netlib.IpDefragger(fragIp6Chan, udpChan, tcpChan)
	// tcp assembly
	go netlib.TcpAssembler(tcpChan, dnsChan, c.filterDnsPort)
	// udp processor
	go netlib.UdpProcessor(udpChan, dnsChan, c.filterDnsPort)

	go func() {
		nbPackets := 0
		lastReceivedTime := time.Now()
		for {
			select {
			case dnsPacket, noMore := <-dnsChan:
				if !noMore {
					goto end
				}

				lastReceivedTime = time.Now()
				// prepare dns message
				dm := dnsutils.DnsMessage{}
				dm.Init()

				dm.NetworkInfo.Family = dnsPacket.IpLayer.EndpointType().String()
				dm.NetworkInfo.QueryIp = dnsPacket.IpLayer.Src().String()
				dm.NetworkInfo.ResponseIp = dnsPacket.IpLayer.Dst().String()
				dm.NetworkInfo.QueryPort = dnsPacket.TransportLayer.Src().String()
				dm.NetworkInfo.ResponsePort = dnsPacket.TransportLayer.Dst().String()
				dm.NetworkInfo.Protocol = dnsPacket.TransportLayer.EndpointType().String()
				dm.NetworkInfo.IpDefragmented = dnsPacket.IpDefragmented
				dm.NetworkInfo.TcpReassembled = dnsPacket.TcpReassembled

				dm.DNS.Payload = dnsPacket.Payload
				dm.DNS.Length = len(dnsPacket.Payload)

				dm.DnsTap.Identity = c.identity
				dm.DnsTap.TimeSec = dnsPacket.Timestamp.Second()
				dm.DnsTap.TimeNsec = int(dnsPacket.Timestamp.UnixNano())

				// count it
				nbPackets++

				// send DNS message to DNS processor
				c.dnsProcessor.GetChannel() <- dm
			case <-time.After(10 * time.Second):
				elapsed := time.Since(lastReceivedTime)
				if elapsed >= 10*time.Second {
					close(fragIp4Chan)
					close(fragIp6Chan)
					close(udpChan)
					close(tcpChan)
					close(dnsChan)
				}
			}
		}
	end:
		c.LogInfo("pcap file [%s]: %d DNS packet(s) detected", fileName, nbPackets)
	}()

	nbPackets := 0
	for {
		packet, err := packetSource.NextPacket()

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			c.LogError("unable to read packet: %s", err)
			break
		}

		nbPackets++

		// some security checks
		if packet.NetworkLayer() == nil {
			continue
		}
		if packet.TransportLayer() == nil {
			continue
		}

		// ipv4 fragmented packet ?
		if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
			ip4 := packet.NetworkLayer().(*layers.IPv4)
			if ip4.Flags&layers.IPv4MoreFragments == 1 || ip4.FragOffset > 0 {
				fragIp4Chan <- packet
				continue
			}
		}

		// ipv6 fragmented packet ?
		if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
			v6frag := packet.Layer(layers.LayerTypeIPv6Fragment)
			if v6frag != nil {
				fragIp6Chan <- packet
				continue
			}
		}

		// tcp or udp packets ?
		if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
			udpChan <- packet
		}
		if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
			tcpChan <- packet
		}

	}

	// remove it ?
	//assembler.FlushAll()
	c.LogInfo("pcap file [%s] processing terminated, %d packet(s) read", fileName, nbPackets)

	// remove it ?
	if c.config.Collectors.FileIngestor.DeleteAfter {
		c.LogInfo("delete file [%s]", fileName)
		os.Remove(filePath)
	}

	// remove event timer for this file
	c.RemoveEvent(filePath)
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

	fileName := filepath.Base(filePath)
	c.LogInfo("processing dnstap file [%s]", fileName)
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
	c.LogInfo("processing of [%s] terminated", fileName)
	if c.config.Collectors.FileIngestor.DeleteAfter {
		c.LogInfo("delete file [%s]", fileName)
		os.Remove(filePath)
	}

	// remove event timer for this file
	c.RemoveEvent(filePath)

	return nil
}

func (c *FileIngestor) RegisterEvent(filePath string) {
	// Get timer.
	c.mu.Lock()
	t, ok := c.watcherTimers[filePath]
	c.mu.Unlock()

	// No timer yet, so create one.
	if !ok {
		t = time.AfterFunc(math.MaxInt64, func() { c.ProcessFile(filePath) })
		t.Stop()

		c.mu.Lock()
		c.watcherTimers[filePath] = t
		c.mu.Unlock()
	}

	// Reset the timer for this path, so it will start from 100ms again.
	t.Reset(waitFor)
}

func (c *FileIngestor) RemoveEvent(filePath string) {
	c.mu.Lock()
	delete(c.watcherTimers, filePath)
	c.mu.Unlock()
}

func (c *FileIngestor) Run() {
	c.LogInfo("starting collector...")

	c.dnsProcessor = NewDnsProcessor(c.config, c.logger, c.name)
	go c.dnsProcessor.Run(c.Loggers())

	// start dnstap subprocessor
	c.dnstapProcessor = NewDnstapProcessor(c.config, c.logger, c.name)
	go c.dnstapProcessor.Run(c.Loggers())

	// read current folder content
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

		switch c.config.Collectors.FileIngestor.WatchMode {
		case dnsutils.MODE_PCAP:
			// process file with pcap extension
			if filepath.Ext(fn) == ".pcap" || filepath.Ext(fn) == ".pcap.gz" {
				go c.ProcessPcap(fn)
			}
		case dnsutils.MODE_DNSTAP:
			// processs dnstap
			if filepath.Ext(fn) == ".fstrm" {
				go c.ProcessDnstap(fn)
			}
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
				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
					return
				}

				// detect activity on file
				if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) {
					continue
				}

				// register the event by the name
				c.RegisterEvent(event.Name)

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
