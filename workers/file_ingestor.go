package workers

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
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
		pkgconfig.ModePCAP,
		pkgconfig.ModeDNSTap:
		return true
	}
	return false
}

type FileIngestor struct {
	*pkgutils.GenericWorker
	watcherTimers   map[string]*time.Timer
	dnsProcessor    DNSProcessor
	dnstapProcessor DNSTapProcessor
	mu              sync.Mutex
}

func NewFileIngestor(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *FileIngestor {
	w := &FileIngestor{
		GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "fileingestor", pkgutils.DefaultBufferSize),
		watcherTimers: make(map[string]*time.Timer)}
	w.SetDefaultRoutes(next)
	w.CheckConfig()
	return w
}

func (w *FileIngestor) CheckConfig() {
	if !IsValidMode(w.GetConfig().Collectors.FileIngestor.WatchMode) {
		w.LogFatal(pkgutils.PrefixLogCollector+"["+w.GetName()+"] - invalid mode: ", w.GetConfig().Collectors.FileIngestor.WatchMode)
	}

	w.LogInfo("watching directory [%s] to find [%s] files",
		w.GetConfig().Collectors.FileIngestor.WatchDir,
		w.GetConfig().Collectors.FileIngestor.WatchMode)
}

func (w *FileIngestor) ProcessFile(filePath string) {
	switch w.GetConfig().Collectors.FileIngestor.WatchMode {
	case pkgconfig.ModePCAP:
		// process file with pcap extension only
		if filepath.Ext(filePath) == ".pcap" || filepath.Ext(filePath) == ".pcap.gz" {
			w.LogInfo("file ready to process %s", filePath)
			go w.ProcessPcap(filePath)
		}
	case pkgconfig.ModeDNSTap:
		// process dnstap
		if filepath.Ext(filePath) == ".fstrm" {
			w.LogInfo("file ready to process %s", filePath)
			go w.ProcessDnstap(filePath)
		}
	}
}

func (w *FileIngestor) ProcessPcap(filePath string) {
	// open the file
	f, err := os.Open(filePath)
	if err != nil {
		w.LogError("unable to read file: %s", err)
		return
	}
	defer f.Close()

	// it is a pcap file ?
	pcapHandler, err := pcapgo.NewReader(f)
	if err != nil {
		w.LogError("unable to read pcap file: %s", err)
		return
	}

	fileName := filepath.Base(filePath)
	w.LogInfo("processing pcap file [%s]...", fileName)

	if pcapHandler.LinkType() != layers.LinkTypeEthernet {
		w.LogError("pcap file [%s] ignored: %s", filePath, pcapHandler.LinkType())
		return
	}

	dnsChan := make(chan netutils.DNSPacket)
	udpChan := make(chan gopacket.Packet)
	tcpChan := make(chan gopacket.Packet)
	fragIP4Chan := make(chan gopacket.Packet)
	fragIP6Chan := make(chan gopacket.Packet)

	packetSource := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.NoCopy = true

	// defrag ipv4
	go netutils.IPDefragger(fragIP4Chan, udpChan, tcpChan, w.GetConfig().Collectors.FileIngestor.PcapDNSPort)
	// defrag ipv6
	go netutils.IPDefragger(fragIP6Chan, udpChan, tcpChan, w.GetConfig().Collectors.FileIngestor.PcapDNSPort)
	// tcp assembly
	go netutils.TCPAssembler(tcpChan, dnsChan, w.GetConfig().Collectors.FileIngestor.PcapDNSPort)
	// udp processor
	go netutils.UDPProcessor(udpChan, dnsChan, w.GetConfig().Collectors.FileIngestor.PcapDNSPort)

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
				dm := dnsutils.DNSMessage{}
				dm.Init()

				dm.NetworkInfo.Family = dnsPacket.IPLayer.EndpointType().String()
				dm.NetworkInfo.QueryIP = dnsPacket.IPLayer.Src().String()
				dm.NetworkInfo.ResponseIP = dnsPacket.IPLayer.Dst().String()
				dm.NetworkInfo.QueryPort = dnsPacket.TransportLayer.Src().String()
				dm.NetworkInfo.ResponsePort = dnsPacket.TransportLayer.Dst().String()
				dm.NetworkInfo.Protocol = dnsPacket.TransportLayer.EndpointType().String()
				dm.NetworkInfo.IPDefragmented = dnsPacket.IPDefragmented
				dm.NetworkInfo.TCPReassembled = dnsPacket.TCPReassembled

				dm.DNS.Payload = dnsPacket.Payload
				dm.DNS.Length = len(dnsPacket.Payload)

				dm.DNSTap.Identity = w.GetConfig().GetServerIdentity()
				dm.DNSTap.TimeSec = dnsPacket.Timestamp.Second()
				dm.DNSTap.TimeNsec = int(dnsPacket.Timestamp.UnixNano())

				// count it
				nbPackets++

				// send DNS message to DNS processor
				w.dnsProcessor.GetChannel() <- dm
			case <-time.After(10 * time.Second):
				elapsed := time.Since(lastReceivedTime)
				if elapsed >= 10*time.Second {
					close(dnsChan)
				}
			}
		}
	end:
		w.LogInfo("pcap file [%s]: %d DNS packet(s) detected", fileName, nbPackets)
	}()

	nbPackets := 0
	for {
		packet, err := packetSource.NextPacket()

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			w.LogError("unable to read packet: %s", err)
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
				fragIP4Chan <- packet
				continue
			}
		}

		// ipv6 fragmented packet ?
		if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
			v6frag := packet.Layer(layers.LayerTypeIPv6Fragment)
			if v6frag != nil {
				fragIP6Chan <- packet
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

	w.LogInfo("pcap file [%s] processing terminated, %d packet(s) read", fileName, nbPackets)

	// remove it ?
	if w.GetConfig().Collectors.FileIngestor.DeleteAfter {
		w.LogInfo("delete file [%s]", fileName)
		os.Remove(filePath)
	}

	// close chan
	close(fragIP4Chan)
	close(fragIP6Chan)
	close(udpChan)
	close(tcpChan)

	// remove event timer for this file
	w.RemoveEvent(filePath)
}

func (w *FileIngestor) ProcessDnstap(filePath string) error {
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
	w.LogInfo("processing dnstap file [%s]", fileName)
	for {
		buf, err := dnstapDecoder.Decode()
		if errors.Is(err, io.EOF) {
			break
		}

		newbuf := make([]byte, len(buf))
		copy(newbuf, buf)

		w.dnstapProcessor.GetChannel() <- newbuf
	}

	// remove it ?
	w.LogInfo("processing of [%s] terminated", fileName)
	if w.GetConfig().Collectors.FileIngestor.DeleteAfter {
		w.LogInfo("delete file [%s]", fileName)
		os.Remove(filePath)
	}

	// remove event timer for this file
	w.RemoveEvent(filePath)

	return nil
}

func (w *FileIngestor) RegisterEvent(filePath string) {
	// Get timer.
	w.mu.Lock()
	t, ok := w.watcherTimers[filePath]
	w.mu.Unlock()

	// No timer yet, so create one.
	if !ok {
		t = time.AfterFunc(math.MaxInt64, func() { w.ProcessFile(filePath) })
		t.Stop()

		w.mu.Lock()
		w.watcherTimers[filePath] = t
		w.mu.Unlock()
	}

	// Reset the timer for this path, so it will start from 100ms again.
	t.Reset(waitFor)
}

func (w *FileIngestor) RemoveEvent(filePath string) {
	w.mu.Lock()
	delete(w.watcherTimers, filePath)
	w.mu.Unlock()
}

func (w *FileIngestor) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	w.dnsProcessor = NewDNSProcessor(w.GetConfig(), w.GetLogger(), w.GetName(), w.GetConfig().Collectors.FileIngestor.ChannelBufferSize)
	go w.dnsProcessor.Run(w.GetDefaultRoutes(), w.GetDroppedRoutes())

	// start dnstap subprocessor
	w.dnstapProcessor = NewDNSTapProcessor(0, "", w.GetConfig(), w.GetLogger(), w.GetName(), w.GetConfig().Collectors.FileIngestor.ChannelBufferSize)
	go w.dnstapProcessor.Run(w.GetDefaultRoutes(), w.GetDroppedRoutes())

	// read current folder content
	entries, err := os.ReadDir(w.GetConfig().Collectors.FileIngestor.WatchDir)
	if err != nil {
		w.LogError("unable to read folder: %s", err)
	}

	for _, entry := range entries {
		// ignore folder
		if entry.IsDir() {
			continue
		}

		// prepare filepath
		fn := filepath.Join(w.GetConfig().Collectors.FileIngestor.WatchDir, entry.Name())

		switch w.GetConfig().Collectors.FileIngestor.WatchMode {
		case pkgconfig.ModePCAP:
			// process file with pcap extension
			if filepath.Ext(fn) == ".pcap" || filepath.Ext(fn) == ".pcap.gz" {
				go w.ProcessPcap(fn)
			}
		case pkgconfig.ModeDNSTap:
			// process dnstap
			if filepath.Ext(fn) == ".fstrm" {
				go w.ProcessDnstap(fn)
			}
		}
	}

	// then watch for new one
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		w.LogFatal(pkgutils.PrefixLogCollector+"["+w.GetName()+"] new watcher: ", err)
	}
	// register the folder to watch
	err = watcher.Add(w.GetConfig().Collectors.FileIngestor.WatchDir)
	if err != nil {
		w.LogFatal(pkgutils.PrefixLogCollector+"["+w.GetName()+"] register folder: ", err)
	}

	for {
		select {
		case <-w.OnStop():
			w.LogInfo("stop to listen...")

			// stop watching
			watcher.Close()

			// stop processors
			w.dnsProcessor.Stop()
			w.dnstapProcessor.Stop()
			return

		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.CheckConfig()

			w.dnsProcessor.ConfigChan <- cfg
			w.dnstapProcessor.ConfigChan <- cfg

		case event, ok := <-watcher.Events:
			if !ok { // Channel was closed (i.e. Watcher.Close() was called).
				return
			}

			// detect activity on file
			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) {
				continue
			}

			// register the event by the name
			w.RegisterEvent(event.Name)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			w.LogError("error:", err)
		}
	}
}
