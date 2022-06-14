package loggers

import (
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	compressPcapSuffix = ".gz"
)

type PcapWriter struct {
	done           chan bool
	channel        chan dnsutils.DnsMessage
	config         *dnsutils.Config
	logger         *logger.Logger
	pcapw          *pcapgo.Writer
	fd             *os.File
	size           int64
	filedir        string
	filename       string
	fileext        string
	fileprefix     string
	commpressTimer *time.Timer
	name           string
}

func NewPcapFile(config *dnsutils.Config, console *logger.Logger, name string) *PcapWriter {
	console.Info("[%s] logger to pcap file - enabled", name)
	o := &PcapWriter{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  console,
		config:  config,
		name:    name,
	}
	o.ReadConfig()

	if err := o.OpenFile(); err != nil {
		o.logger.Fatal("["+name+"] unable to create file: ", err)
	}

	return o
}

func (c *PcapWriter) ReadConfig() {
	c.filedir = filepath.Dir(c.config.Loggers.PcapFile.FilePath)
	c.filename = filepath.Base(c.config.Loggers.PcapFile.FilePath)
	c.fileext = filepath.Ext(c.filename)
	c.fileprefix = strings.TrimSuffix(c.filename, c.fileext)
}

func (o *PcapWriter) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to pcap file - "+msg, v...)
}

func (o *PcapWriter) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to pcap file - "+msg, v...)
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
	if dm.NetworkInfo.Family == "INET6" {
		srcIp, dstIp = "::", "::"
	}

	if dm.NetworkInfo.QueryIp != "-" {
		srcIp = dm.NetworkInfo.QueryIp
		srcPort, _ = strconv.Atoi(dm.NetworkInfo.QueryPort)
	}
	if dm.NetworkInfo.ResponseIp != "-" {
		dstIp = dm.NetworkInfo.ResponseIp
		dstPort, _ = strconv.Atoi(dm.NetworkInfo.ResponsePort)
	}

	// reverse destination and source
	if dm.DNS.Type == dnsutils.DnsReply {
		srcIp_tmp, srcPort_tmp := srcIp, srcPort
		srcIp, srcPort = dstIp, dstPort
		dstIp, dstPort = srcIp_tmp, srcPort_tmp
	}
	return srcIp, srcPort, dstIp, dstPort
}

func (o *PcapWriter) OpenFile() error {
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

func (o *PcapWriter) Cleanup() error {
	// remove old files ?
	files, err := ioutil.ReadDir(o.filedir)
	if err != nil {
		return err
	}

	logFiles := []int{}
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		// extract timestamp from filename
		re := regexp.MustCompile(`^` + o.fileprefix + `-(?P<ts>\d+)` + o.fileext)
		matches := re.FindStringSubmatch(f.Name())

		if len(matches) == 0 {
			continue
		}

		// convert timestamp to int
		tsIndex := re.SubexpIndex("ts")
		i, err := strconv.Atoi(matches[tsIndex])
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
			filename := fmt.Sprintf("%s-%d%s", o.fileprefix, logFiles[i], o.fileext)
			f := filepath.Join(o.filedir, filename)
			if _, err := os.Stat(f); os.IsNotExist(err) {
				f = filepath.Join(o.filedir, filename+compressPcapSuffix)
			}

			os.Remove(f)
		}
	}

	return nil
}

func (o *PcapWriter) Compress() {
	files, err := ioutil.ReadDir(o.filedir)
	if err != nil {
		o.LogError("unable to list all files: %s", err)
	}

	for _, f := range files {
		// ignore folder
		if f.IsDir() {
			continue
		}

		matched, _ := regexp.MatchString(`^`+o.fileprefix+`-\d+`+o.fileext+`$`, f.Name())
		if matched {
			src := filepath.Join(o.filedir, f.Name())
			dst := filepath.Join(o.filedir, f.Name()+compressSuffix)

			fl, err := os.Open(src)
			if err != nil {
				o.LogError("compress - failed to open pcap file: ", err)
				continue
			}
			defer fl.Close()

			fi, err := os.Stat(src)
			if err != nil {
				o.LogError("compress - failed to stat pcap file: ", err)
				continue
			}

			gzf, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
			if err != nil {
				o.LogError("compress - failed to open compressed pcap file: ", err)
				continue
			}
			defer gzf.Close()

			gz := gzip.NewWriter(gzf)

			if _, err := io.Copy(gz, fl); err != nil {
				o.LogError("compress - failed to compress pcap file: ", err)
				os.Remove(dst)
				continue
			}
			if err := gz.Close(); err != nil {
				o.LogError("compress - failed to close gz writer: ", err)
				os.Remove(dst)
				continue
			}
			if err := gzf.Close(); err != nil {
				o.LogError("compress - failed to close gz file: ", err)
				os.Remove(dst)
				continue
			}

			if err := fl.Close(); err != nil {
				o.LogError("compress - failed to close pcap file: ", err)
				os.Remove(dst)
				continue
			}
			if err := os.Remove(src); err != nil {
				o.LogError("compress - failed to remove pcap file: ", err)
				os.Remove(dst)
				continue
			}

		}
	}

	o.commpressTimer.Reset(time.Duration(o.config.Loggers.PcapFile.CompressInterval) * time.Second)
}

func (o *PcapWriter) PostRotateCommand(filename string) {
	if len(o.config.Loggers.PcapFile.PostRotateCommand) > 0 {
		out, err := exec.Command(o.config.Loggers.PcapFile.PostRotateCommand, filename).Output()
		if err != nil {
			o.LogError("postrotate command error: %s", err)
			o.LogError("postrotate output: %s", out)
		} else {
			if o.config.Loggers.PcapFile.PostRotateDelete {
				os.Remove(filename)
			}
		}
	}
}

func (o *PcapWriter) Rotate() error {
	// closing current file
	o.fd.Close()

	// Rename log file
	bfpath := filepath.Join(o.filedir, fmt.Sprintf("%s-%d%s", o.fileprefix, time.Now().Unix(), o.fileext))
	err := os.Rename(o.config.Loggers.PcapFile.FilePath, bfpath)
	if err != nil {
		return err
	}

	// post rotate command?
	o.PostRotateCommand(bfpath)

	// keep only max files
	err = o.Cleanup()
	if err != nil {
		o.LogError("unable to cleanup pcap files: %s", err)
		return err
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
			o.LogError("failed to rotate file: %s", err)
			return
		}
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec)),
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

	o.commpressTimer = time.NewTimer(time.Duration(o.config.Loggers.PcapFile.CompressInterval) * time.Second)
LOOP:
	for {
		select {
		case dm, opened := <-o.channel:
			if !opened {
				o.LogInfo("channel closed")
				break LOOP
			}

			// prepare ip
			srcIp, srcPort, dstIp, dstPort := o.GetIpPort(&dm)

			// packet layer array
			pkt := []gopacket.SerializableLayer{}

			// set ip and transport
			if dm.NetworkInfo.Family == "INET6" && dm.NetworkInfo.Protocol == "UDP" {
				eth.EthernetType = layers.EthernetTypeIPv6
				ip6.SrcIP = net.ParseIP(srcIp)
				ip6.DstIP = net.ParseIP(dstIp)
				ip6.NextHeader = layers.IPProtocolUDP
				udp.SrcPort = layers.UDPPort(srcPort)
				udp.DstPort = layers.UDPPort(dstPort)
				udp.SetNetworkLayerForChecksum(ip6)

				pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6, eth)

			} else if dm.NetworkInfo.Family == "INET6" && dm.NetworkInfo.Protocol == "TCP" {
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
				binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.DNS.Length))
				pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip6, eth)

			} else if dm.NetworkInfo.Family == "INET" && dm.NetworkInfo.Protocol == "UDP" {
				eth.EthernetType = layers.EthernetTypeIPv4
				ip4.SrcIP = net.ParseIP(srcIp)
				ip4.DstIP = net.ParseIP(dstIp)
				ip4.Protocol = layers.IPProtocolUDP
				udp.SrcPort = layers.UDPPort(srcPort)
				udp.DstPort = layers.UDPPort(dstPort)
				udp.SetNetworkLayerForChecksum(ip4)

				pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4, eth)

			} else if dm.NetworkInfo.Family == "INET" && dm.NetworkInfo.Protocol == "TCP" {
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
				binary.BigEndian.PutUint16(dnsLengthField[0:], uint16(dm.DNS.Length))
				pkt = append(pkt, gopacket.Payload(append(dnsLengthField, dm.DNS.Payload...)), tcp, ip4, eth)

			} else {
				// ignore other packet
				continue
			}

			// create the packet
			o.Write(dm, pkt)

		case <-o.commpressTimer.C:
			if o.config.Loggers.PcapFile.Compress {
				o.Compress()
			}
		}
	}
	o.LogInfo("run terminated")

	// the job is done
	o.done <- true
}
