package loggers

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	compressSuffix = ".gz"
)

func IsValidMode(mode string) bool {
	switch mode {
	case
		dnsutils.MODE_TEXT,
		dnsutils.MODE_JSON,
		dnsutils.MODE_PCAP:
		return true
	}
	return false
}

func GetIpPort(dm *dnsutils.DnsMessage) (string, int, string, int) {
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

type LogFile struct {
	done           chan bool
	channel        chan dnsutils.DnsMessage
	writerPlain    *bufio.Writer
	writerPcap     *pcapgo.Writer
	config         *dnsutils.Config
	logger         *logger.Logger
	fileFd         *os.File
	fileSize       int64
	fileDir        string
	fileName       string
	fileExt        string
	filePrefix     string
	commpressTimer *time.Timer
	textFormat     []string
	name           string
}

func NewLogFile(config *dnsutils.Config, logger *logger.Logger, name string) *LogFile {
	logger.Info("[%s] logger file - enabled", name)
	l := &LogFile{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		config:  config,
		logger:  logger,
		name:    name,
	}

	l.ReadConfig()

	if err := l.OpenFile(); err != nil {
		l.logger.Fatal("["+name+"] logger file - unable to open output file:", err)
	}

	return l
}

func (l *LogFile) GetName() string { return l.name }

func (l *LogFile) SetLoggers(loggers []dnsutils.Worker) {}

func (l *LogFile) Channel() chan dnsutils.DnsMessage {
	return l.channel
}

func (l *LogFile) ReadConfig() {
	if !IsValidMode(l.config.Loggers.LogFile.Mode) {
		l.logger.Fatal("logger file - invalid mode: ", l.config.Loggers.LogFile.Mode)
	}
	l.fileDir = filepath.Dir(l.config.Loggers.LogFile.FilePath)
	l.fileName = filepath.Base(l.config.Loggers.LogFile.FilePath)
	l.fileExt = filepath.Ext(l.fileName)
	l.filePrefix = strings.TrimSuffix(l.fileName, l.fileExt)

	if len(l.config.Loggers.LogFile.TextFormat) > 0 {
		l.textFormat = strings.Fields(l.config.Loggers.LogFile.TextFormat)
	} else {
		l.textFormat = strings.Fields(l.config.Global.TextFormat)
	}

	l.LogInfo("running in mode: %s", l.config.Loggers.LogFile.Mode)
}

func (l *LogFile) LogInfo(msg string, v ...interface{}) {
	l.logger.Info("["+l.name+"] logger file - "+msg, v...)
}

func (l *LogFile) LogError(msg string, v ...interface{}) {
	l.logger.Error("["+l.name+"] logger file - "+msg, v...)
}

func (l *LogFile) Stop() {
	l.LogInfo("stopping...")

	// close output channel
	l.LogInfo("closing channel")
	close(l.channel)

	// closing file
	l.fileFd.Close()

	// read done channel and block until run is terminated
	<-l.done
	close(l.done)
}

func (l *LogFile) Cleanup() error {
	if l.config.Loggers.LogFile.MaxFiles == 0 {
		return nil
	}

	// remove old files ? keep only max files number
	entries, err := os.ReadDir(l.fileDir)
	if err != nil {
		return err
	}

	logFiles := []int{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// extract timestamp from filename
		re := regexp.MustCompile(`^` + l.filePrefix + `-(?P<ts>\d+)` + l.fileExt)
		matches := re.FindStringSubmatch(entry.Name())

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
	diff_nb := len(logFiles) - l.config.Loggers.LogFile.MaxFiles
	if diff_nb > 0 {
		for i := 0; i < diff_nb; i++ {
			filename := fmt.Sprintf("%s-%d%s", l.filePrefix, logFiles[i], l.fileExt)
			f := filepath.Join(l.fileDir, filename)
			if _, err := os.Stat(f); os.IsNotExist(err) {
				f = filepath.Join(l.fileDir, filename+compressSuffix)
			}

			// ignore errors on deletion
			os.Remove(f)
		}
	}

	return nil
}

func (l *LogFile) OpenFile() error {

	fd, err := os.OpenFile(l.config.Loggers.LogFile.FilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	l.fileFd = fd

	fileinfo, err := os.Stat(l.config.Loggers.LogFile.FilePath)
	if err != nil {
		return err
	}

	l.fileSize = fileinfo.Size()

	switch l.config.Loggers.LogFile.Mode {
	case dnsutils.MODE_TEXT, dnsutils.MODE_JSON:
		l.writerPlain = bufio.NewWriter(fd)
	case dnsutils.MODE_PCAP:
		l.writerPcap = pcapgo.NewWriter(fd)
		if l.fileSize == 0 {
			if err := l.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				return err
			}
		}
	}

	return nil
}

func (o *LogFile) GetMaxSize() int64 {
	return int64(1024*1024) * int64(o.config.Loggers.LogFile.MaxSize)
}

func (l *LogFile) CompressFile() {
	entries, err := os.ReadDir(l.fileDir)
	if err != nil {
		l.LogError("unable to list all files: %s", err)
		return
	}

	for _, entry := range entries {
		// ignore folder
		if entry.IsDir() {
			continue
		}

		matched, _ := regexp.MatchString(`^`+l.filePrefix+`-\d+`+l.fileExt+`$`, entry.Name())
		if matched {
			src := filepath.Join(l.fileDir, entry.Name())
			dst := filepath.Join(l.fileDir, entry.Name()+compressSuffix)

			fl, err := os.Open(src)
			if err != nil {
				l.LogError("compress - failed to open file: ", err)
				continue
			}
			defer fl.Close()

			fi, err := os.Stat(src)
			if err != nil {
				l.LogError("compress - failed to stat file: ", err)
				continue
			}

			gzf, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
			if err != nil {
				l.LogError("compress - failed to open compressed file: ", err)
				continue
			}
			defer gzf.Close()

			gz := gzip.NewWriter(gzf)

			if _, err := io.Copy(gz, fl); err != nil {
				l.LogError("compress - failed to compress file: ", err)
				os.Remove(dst)
				continue
			}
			if err := gz.Close(); err != nil {
				l.LogError("compress - failed to close gz writer: ", err)
				os.Remove(dst)
				continue
			}
			if err := gzf.Close(); err != nil {
				l.LogError("compress - failed to close gz file: ", err)
				os.Remove(dst)
				continue
			}

			if err := fl.Close(); err != nil {
				l.LogError("compress - failed to close log file: ", err)
				os.Remove(dst)
				continue
			}
			if err := os.Remove(src); err != nil {
				l.LogError("compress - failed to remove log file: ", err)
				os.Remove(dst)
				continue
			}

			// post rotate command?
			l.CompressPostRotateCommand(dst)
		}
	}

	l.commpressTimer.Reset(time.Duration(l.config.Loggers.LogFile.CompressInterval) * time.Second)
}

func (l *LogFile) PostRotateCommand(filename string) {
	if len(l.config.Loggers.LogFile.PostRotateCommand) > 0 {
		l.LogInfo("execute postrotate command: %s", filename)
		out, err := exec.Command(l.config.Loggers.LogFile.PostRotateCommand, filename).Output()
		if err != nil {
			l.LogError("postrotate command error: %s", err)
		} else {
			if l.config.Loggers.LogFile.PostRotateDelete {
				os.Remove(filename)
			}
		}
		l.LogInfo("compress - postcommand output: %s", out)
	}
}

func (l *LogFile) CompressPostRotateCommand(filename string) {
	if len(l.config.Loggers.LogFile.CompressPostCommand) > 0 {

		l.LogInfo("execute compress postrotate command: %s", filename)
		out, err := exec.Command(l.config.Loggers.LogFile.CompressPostCommand, filename).Output()
		if err != nil {
			l.LogError("compress - postcommand error: %s", err)
		}
		l.LogInfo("compress - postcommand output: %s", out)
	}
}

func (l *LogFile) FlushWriter() {
	switch l.config.Loggers.LogFile.Mode {
	case dnsutils.MODE_TEXT:
		l.writerPlain.Flush()
	case dnsutils.MODE_JSON:
		l.writerPlain.Flush()
	}
}

func (l *LogFile) RotateFile() error {
	// close existing file
	l.FlushWriter()
	if err := l.fileFd.Close(); err != nil {
		return err
	}

	// Rename current log file
	bfpath := filepath.Join(l.fileDir, fmt.Sprintf("%s-%d%s", l.filePrefix, time.Now().UnixNano(), l.fileExt))
	err := os.Rename(l.config.Loggers.LogFile.FilePath, bfpath)
	if err != nil {
		return err
	}

	// post rotate command?
	l.PostRotateCommand(bfpath)

	// keep only max files
	err = l.Cleanup()
	if err != nil {
		l.LogError("unable to cleanup log files: %s", err)
		return err
	}

	// re-create new one
	if err := l.OpenFile(); err != nil {
		l.LogError("unable to re-create file: %s", err)
		return err
	}

	return nil
}

func (l *LogFile) WriteToPcap(dm dnsutils.DnsMessage, pkt []gopacket.SerializableLayer) {
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
	bufSize := len(buf.Bytes())

	if (l.fileSize + int64(bufSize)) > l.GetMaxSize() {
		if err := l.RotateFile(); err != nil {
			l.LogError("failed to rotate file: %s", err)
			return
		}
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec)),
		CaptureLength: bufSize,
		Length:        bufSize,
	}

	l.writerPcap.WritePacket(ci, buf.Bytes())

	// increase size file
	l.fileSize += int64(bufSize)
}

func (l *LogFile) WriteToPlain(data []byte) {
	dataSize := int64(len(data))

	// rotate file ?
	if (l.fileSize + dataSize) > l.GetMaxSize() {
		if err := l.RotateFile(); err != nil {
			l.LogError("failed to rotate file: %s", err)
			return
		}
	}

	// write log to file
	n, _ := l.writerPlain.Write(data)

	// increase size file
	l.fileSize += int64(n)
}

func (l *LogFile) Run() {
	l.LogInfo("running in background...")

	// prepare transforms
	subprocessors := transformers.NewTransforms(&l.config.OutgoingTransformers, l.logger, l.name)

	// prepare some timers
	flushInterval := time.Duration(l.config.Loggers.LogFile.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)
	l.commpressTimer = time.NewTimer(time.Duration(l.config.Loggers.LogFile.CompressInterval) * time.Second)

	// for pcap only
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip6 := &layers.IPv6{Version: 6}
	udp := &layers.UDP{}
	tcp := &layers.TCP{}

	buffer := new(bytes.Buffer)
LOOP:
	for {
		select {
		case dm, opened := <-l.channel:
			if !opened {
				l.LogInfo("channel closed")
				break LOOP
			}

			// apply tranforms
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// write to file
			switch l.config.Loggers.LogFile.Mode {

			// with basic text mode
			case dnsutils.MODE_TEXT:
				delimiter := "\n"
				l.WriteToPlain(dm.Bytes(l.textFormat, delimiter))

			// with json mode
			case dnsutils.MODE_JSON:
				json.NewEncoder(buffer).Encode(dm)
				l.WriteToPlain(buffer.Bytes())
				buffer.Reset()

			// with pcap mode
			case dnsutils.MODE_PCAP:
				// prepare ip
				srcIp, srcPort, dstIp, dstPort := GetIpPort(&dm)

				// packet layer array
				pkt := []gopacket.SerializableLayer{}

				// set ip and transport
				if dm.NetworkInfo.Family == dnsutils.PROTO_IPV6 && dm.NetworkInfo.Protocol == dnsutils.PROTO_UDP {
					eth.EthernetType = layers.EthernetTypeIPv6
					ip6.SrcIP = net.ParseIP(srcIp)
					ip6.DstIP = net.ParseIP(dstIp)
					ip6.NextHeader = layers.IPProtocolUDP
					udp.SrcPort = layers.UDPPort(srcPort)
					udp.DstPort = layers.UDPPort(dstPort)
					udp.SetNetworkLayerForChecksum(ip6)

					pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip6, eth)

				} else if dm.NetworkInfo.Family == dnsutils.PROTO_IPV6 && dm.NetworkInfo.Protocol == dnsutils.PROTO_TCP {
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

				} else if dm.NetworkInfo.Family == dnsutils.PROTO_IPV4 && dm.NetworkInfo.Protocol == dnsutils.PROTO_UDP {
					eth.EthernetType = layers.EthernetTypeIPv4
					ip4.SrcIP = net.ParseIP(srcIp)
					ip4.DstIP = net.ParseIP(dstIp)
					ip4.Protocol = layers.IPProtocolUDP
					udp.SrcPort = layers.UDPPort(srcPort)
					udp.DstPort = layers.UDPPort(dstPort)
					udp.SetNetworkLayerForChecksum(ip4)

					pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4, eth)

				} else if dm.NetworkInfo.Family == dnsutils.PROTO_IPV4 && dm.NetworkInfo.Protocol == dnsutils.PROTO_TCP {
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
				l.WriteToPcap(dm, pkt)
			}

		case <-flushTimer.C:
			// flush writer
			l.FlushWriter()

			// reset flush timer and buffer
			buffer.Reset()
			flushTimer.Reset(flushInterval)

		case <-l.commpressTimer.C:
			if l.config.Loggers.LogFile.Compress {
				l.CompressFile()
			}

		}
	}

	// stop timer
	flushTimer.Stop()
	l.commpressTimer.Stop()

	// flush writer
	l.FlushWriter()

	l.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	l.done <- true
}
