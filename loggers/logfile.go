package loggers

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
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

	framestream "github.com/farsightsec/golang-framestream"
)

const (
	compressSuffix = ".gz"
)

func IsValidMode(mode string) bool {
	switch mode {
	case
		dnsutils.MODE_TEXT,
		dnsutils.MODE_JSON,
		dnsutils.MODE_FLATJSON,
		dnsutils.MODE_PCAP,
		dnsutils.MODE_DNSTAP:
		return true
	}
	return false
}

type LogFile struct {
	done           chan bool
	channel        chan dnsutils.DnsMessage
	writerPlain    *bufio.Writer
	writerPcap     *pcapgo.Writer
	writerDnstap   *framestream.Encoder
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
	l.LogInfo("closing dns message channel")
	close(l.channel)

	// closing file
	l.LogInfo("closing log file")
	if l.config.Loggers.LogFile.Mode == dnsutils.MODE_DNSTAP {
		l.writerDnstap.Close()
	}
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
	case dnsutils.MODE_TEXT, dnsutils.MODE_JSON, dnsutils.MODE_FLATJSON:
		l.writerPlain = bufio.NewWriter(fd)

	case dnsutils.MODE_PCAP:
		l.writerPcap = pcapgo.NewWriter(fd)
		if l.fileSize == 0 {
			if err := l.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				return err
			}
		}

	case dnsutils.MODE_DNSTAP:
		fsOptions := &framestream.EncoderOptions{ContentType: []byte("protobuf:dnstap.Dnstap"), Bidirectional: false}
		l.writerDnstap, err = framestream.NewEncoder(fd, fsOptions)
		if err != nil {
			return err
		}

	}

	l.LogInfo("file opened with success: %s", l.config.Loggers.LogFile.FilePath)
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

func (l *LogFile) FlushWriters() {
	switch l.config.Loggers.LogFile.Mode {
	case dnsutils.MODE_TEXT, dnsutils.MODE_JSON, dnsutils.MODE_FLATJSON:
		l.writerPlain.Flush()
	case dnsutils.MODE_DNSTAP:
		l.writerDnstap.Flush()
	}
}

func (l *LogFile) RotateFile() error {
	// close writer and existing file
	l.FlushWriters()

	if l.config.Loggers.LogFile.Mode == dnsutils.MODE_DNSTAP {
		l.writerDnstap.Close()
	}

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

func (l *LogFile) WriteToDnstap(data []byte) {
	dataSize := int64(len(data))

	// rotate file ?
	if (l.fileSize + dataSize) > l.GetMaxSize() {
		if err := l.RotateFile(); err != nil {
			l.LogError("failed to rotate file: %s", err)
			return
		}
	}

	// write log to file
	n, _ := l.writerDnstap.Write(data)

	// increase size file
	l.fileSize += int64(n)
}

func (l *LogFile) Run() {
	l.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, l.channel)
	subprocessors := transformers.NewTransforms(&l.config.OutgoingTransformers, l.logger, l.name, listChannel)

	// prepare some timers
	flushInterval := time.Duration(l.config.Loggers.LogFile.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)
	l.commpressTimer = time.NewTimer(time.Duration(l.config.Loggers.LogFile.CompressInterval) * time.Second)

	buffer := new(bytes.Buffer)
	var data []byte
	var err error
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
				l.WriteToPlain(dm.Bytes(l.textFormat,
					l.config.Global.TextFormatDelimiter,
					l.config.Global.TextFormatBoundary))

				var delimiter bytes.Buffer
				delimiter.WriteString("\n")
				l.WriteToPlain(delimiter.Bytes())

			// with json mode
			case dnsutils.MODE_FLATJSON:
				flat, err := dm.Flatten()
				if err != nil {
					l.LogError("flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				l.WriteToPlain(buffer.Bytes())
				buffer.Reset()

			// with json mode
			case dnsutils.MODE_JSON:
				json.NewEncoder(buffer).Encode(dm)
				l.WriteToPlain(buffer.Bytes())
				buffer.Reset()

			// with dnstap mode
			case dnsutils.MODE_DNSTAP:
				data, err = dm.ToDnstap()
				if err != nil {
					l.LogError("failed to encode to DNStap protobuf: %s", err)
					continue
				}
				l.WriteToDnstap(data)

			// with pcap mode
			case dnsutils.MODE_PCAP:
				pkt, err := dm.ToPacketLayer()
				if err != nil {
					l.LogError("failed to encode to packet layer: %s", err)
					continue
				}

				// write the packet
				l.WriteToPcap(dm, pkt)
			}

		case <-flushTimer.C:
			// flush writer
			l.FlushWriters()

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
	l.FlushWriters()

	l.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	l.done <- true
}
