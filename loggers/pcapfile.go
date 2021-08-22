package loggers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PcapWriter struct {
	done    chan bool
	channel chan dnsutils.DnsMessage
	mode    string
	config  *dnsutils.Config
	logger  *logger.Logger
	stdout  *log.Logger
	pcapw   *pcapgo.Writer
	fd      *os.File
	size    int64
}

func NewPcapFile(config *dnsutils.Config, console *logger.Logger) *PcapWriter {
	console.Info("logger to pcap file - enabled")
	o := &PcapWriter{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  console,
		config:  config,
		stdout:  log.New(os.Stdout, "", 0),
	}
	o.ReadConfig()

	if err := o.OpenFile(); err != nil {
		o.logger.Fatal("unable to create file: ", err)
	}

	return o
}

func (c *PcapWriter) ReadConfig() {
	c.mode = c.config.Loggers.Stdout.Mode
}

func (c *PcapWriter) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("logger to pcap file - "+msg, v...)
}

func (c *PcapWriter) LogError(msg string, v ...interface{}) {
	c.logger.Error("logger to pcap file - "+msg, v...)
}

func (o *PcapWriter) SetBuffer(b *bytes.Buffer) {
	o.stdout.SetOutput(b)
}

func (o *PcapWriter) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *PcapWriter) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// closing file
	o.fd.Close()

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *PcapWriter) GetIpPort(dm *dnsutils.DnsMessage) (string, int, string, int) {
	srcIp, srcPort := "0.0.0.0", 53
	dstIp, dstPort := "0.0.0.0", 53
	if dm.Family == "INET6" {
		srcIp, dstIp = "::", "::"
	}

	if dm.QueryIp != "-" {
		srcIp = dm.QueryIp
		srcPort, _ = strconv.Atoi(dm.QueryPort)
	}
	if dm.ResponseIp != "-" {
		dstIp = dm.ResponseIp
		dstPort, _ = strconv.Atoi(dm.ResponsePort)
	}

	// reverse destination and source
	if dm.Type == "reply" {
		srcIp_tmp, srcPort_tmp := srcIp, srcPort
		srcIp, srcPort = dstIp, dstPort
		dstIp, dstPort = srcIp_tmp, srcPort_tmp
	}
	return srcIp, srcPort, dstIp, dstPort
}

func (o *PcapWriter) OpenFile() error {
	o.LogInfo("opening  pcap file: %s", o.config.Loggers.PcapFile.FilePath)

	var err error
	o.fd, err = os.OpenFile(o.config.Loggers.PcapFile.FilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	fileinfo, err := os.Stat(o.config.Loggers.PcapFile.FilePath)
	if err != nil {
		return err
	}
	o.size = fileinfo.Size()

	o.pcapw = pcapgo.NewWriter(o.fd)
	if o.size == 0 {
		if err := o.pcapw.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			return err
		}
	}

	return nil
}

func (o *PcapWriter) MaxSize() int64 {
	return int64(1024*1024) * int64(o.config.Loggers.PcapFile.MaxSize)
}

func (o *PcapWriter) Rotate() error {
	// closing current file
	o.fd.Close()

	// Rename log file
	filedir := filepath.Dir(o.config.Loggers.PcapFile.FilePath)
	filename := filepath.Base(o.config.Loggers.PcapFile.FilePath)
	fileext := filepath.Ext(filename)
	fileprefix := filename[:len(filename)-len(fileext)]

	now := time.Now()
	timestamp := now.Unix()

	rfpath := filepath.Join(filedir, fmt.Sprintf("%s-%d%s", fileprefix, timestamp, fileext))

	err := os.Rename(o.config.Loggers.PcapFile.FilePath, rfpath)
	if err != nil {
		o.LogError("unable to rename pcap file: %s", err)
	}

	// remove old files ?
	files, err := ioutil.ReadDir(filedir)
	if err != nil {
		o.LogError("unable to list log file: %s", err)
	}

	logFiles := []int{}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		// extract timestamp from filename
		fn := f.Name()
		ts := fn[len(fileprefix)+1 : len(fn)-len(fileext)]

		// convert timestamp to int
		i, err := strconv.Atoi(ts)
		if err != nil {
			continue
		}
		logFiles = append(logFiles, i)
	}
	sort.Ints(logFiles)

	// too much log files ?
	diff_nb := len(logFiles) - o.config.Loggers.PcapFile.MaxFiles
	if diff_nb > 0 {
		for i := 0; i < diff_nb; i++ {
			f := filepath.Join(filedir, fmt.Sprintf("%s-%d%s", fileprefix, logFiles[i], fileext))
			err := os.Remove(f)
			if err != nil {
				o.LogError("unable to delete pcap file: %s", err)
			}

		}
	}

	// re-create the main log file.
	if err := o.OpenFile(); err != nil {
		o.LogError("unable to re-create pcap file: %s", err)
	}

	return nil
}

func (o *PcapWriter) Write(dm dnsutils.DnsMessage, pkt []gopacket.SerializableLayer) {
	// create the packet with the layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for _, l := range pkt {
		l.SerializeTo(buf, opts)
	}

	// rotate pcap file ?
	write_len := len(buf.Bytes())

	if (o.size + int64(write_len)) > o.MaxSize() {
		if err := o.Rotate(); err != nil {
			return
		}
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(int64(dm.TimeSec), int64(dm.TimeNsec)),
		CaptureLength: write_len,
		Length:        write_len,
	}

	o.pcapw.WritePacket(ci, buf.Bytes())

	// increase size file
	o.size += int64(write_len)
}

func (o *PcapWriter) Run() {
	o.LogInfo("running in background...")

	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip6 := &layers.IPv6{Version: 6}
	udp := &layers.UDP{}
	tcp := &layers.TCP{}
	for dm := range o.channel {
		// prepare ip
		srcIp, srcPort, dstIp, dstPort := o.GetIpPort(&dm)

		// packet layer array
		pkt := []gopacket.SerializableLayer{}

		// set ip and transport
		if dm.Family == "INET6" && dm.Protocol == "UDP" {
			eth.EthernetType = layers.EthernetTypeIPv6
			ip6.SrcIP = net.ParseIP(srcIp)
			ip6.DstIP = net.ParseIP(dstIp)
			ip6.NextHeader = layers.IPProtocolUDP
			udp.SrcPort = layers.UDPPort(srcPort)
			udp.DstPort = layers.UDPPort(dstPort)
			udp.SetNetworkLayerForChecksum(ip6)

			pkt = append(pkt, gopacket.Payload(dm.Payload), udp, ip6, eth)

		} else if dm.Family == "INET6" && dm.Protocol == "TCP" {
			eth.EthernetType = layers.EthernetTypeIPv6
			ip6.SrcIP = net.ParseIP(srcIp)
			ip6.DstIP = net.ParseIP(dstIp)
			ip6.NextHeader = layers.IPProtocolTCP
			tcp.SrcPort = layers.TCPPort(srcPort)
			tcp.DstPort = layers.TCPPort(dstPort)
			tcp.PSH = true
			tcp.Window = 65535
			tcp.SetNetworkLayerForChecksum(ip6)

			dnsLengthField := make([]byte, 2)
			binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.Length))
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.Payload...)), tcp, ip6, eth)

		} else if dm.Family == "INET" && dm.Protocol == "UDP" {
			eth.EthernetType = layers.EthernetTypeIPv4
			ip4.SrcIP = net.ParseIP(srcIp)
			ip4.DstIP = net.ParseIP(dstIp)
			ip4.Protocol = layers.IPProtocolUDP
			udp.SrcPort = layers.UDPPort(srcPort)
			udp.DstPort = layers.UDPPort(dstPort)
			udp.SetNetworkLayerForChecksum(ip4)

			pkt = append(pkt, gopacket.Payload(dm.Payload), udp, ip4, eth)

		} else if dm.Family == "INET" && dm.Protocol == "TCP" {
			// SYN
			eth.EthernetType = layers.EthernetTypeIPv4
			ip4.SrcIP = net.ParseIP(srcIp)
			ip4.DstIP = net.ParseIP(dstIp)
			ip4.Protocol = layers.IPProtocolTCP
			tcp.SrcPort = layers.TCPPort(srcPort)
			tcp.DstPort = layers.TCPPort(dstPort)
			tcp.PSH = true
			tcp.Window = 65535
			tcp.SetNetworkLayerForChecksum(ip4)

			dnsLengthField := make([]byte, 2)
			binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.Length))
			pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.Payload...)), tcp, ip4, eth)

		} else {
			// ignore other packet
			continue
		}

		// create the packet
		o.Write(dm, pkt)
	}
	o.LogInfo("run terminated")

	// the job is done
	o.done <- true
}
