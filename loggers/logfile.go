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
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
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
		pkgconfig.ModeText,
		pkgconfig.ModeJSON,
		pkgconfig.ModeFlatJSON,
		pkgconfig.ModePCAP,
		pkgconfig.ModeDNSTap:
		return true
	}
	return false
}

type LogFile struct {
	stopProcess    chan bool
	doneProcess    chan bool
	stopRun        chan bool
	doneRun        chan bool
	inputChan      chan dnsutils.DNSMessage
	outputChan     chan dnsutils.DNSMessage
	writerPlain    *bufio.Writer
	writerPcap     *pcapgo.Writer
	writerDnstap   *framestream.Encoder
	config         *pkgconfig.Config
	configChan     chan *pkgconfig.Config
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
	// droppedCount   map[string]int
	// dropped        chan string
	// droppedRoutes  []pkgutils.Worker
	// defaultRoutes  []pkgutils.Worker
	RoutingHandler pkgutils.RoutingHandler
}

func NewLogFile(config *pkgconfig.Config, logger *logger.Logger, name string) *LogFile {
	logger.Info("[%s] logger=file - enabled", name)
	lf := &LogFile{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DNSMessage, config.Loggers.LogFile.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DNSMessage, config.Loggers.LogFile.ChannelBufferSize),
		config:      config,
		configChan:  make(chan *pkgconfig.Config),
		logger:      logger,
		name:        name,
		// dropped:      make(chan string),
		// droppedCount: map[string]int{},
		RoutingHandler: pkgutils.NewRoutingHandler(config, logger, name),
	}

	lf.ReadConfig()

	if err := lf.OpenFile(); err != nil {
		lf.logger.Fatal("["+name+"] logger=file - unable to open output file:", err)
	}

	return lf
}

func (lf *LogFile) GetName() string { return lf.name }

func (lf *LogFile) AddDroppedRoute(wrk pkgutils.Worker) {
	// lf.droppedRoutes = append(lf.droppedRoutes, wrk)
	lf.RoutingHandler.AddDroppedRoute(wrk)
}

func (lf *LogFile) AddDefaultRoute(wrk pkgutils.Worker) {
	// lf.defaultRoutes = append(lf.defaultRoutes, wrk)
	lf.RoutingHandler.AddDefaultRoute(wrk)
}

// func (lf *LogFile) GetDefaultRoutes() ([]chan dnsutils.DNSMessage, []string) {
// 	return pkgutils.GetActiveRoutes(lf.defaultRoutes)
// }

// func (lf *LogFile) GetDroppedRoutes() ([]chan dnsutils.DNSMessage, []string) {
// 	return pkgutils.GetActiveRoutes(lf.droppedRoutes)
// }

func (lf *LogFile) SetLoggers(loggers []pkgutils.Worker) {}

func (lf *LogFile) GetInputChannel() chan dnsutils.DNSMessage {
	return lf.inputChan
}

func (lf *LogFile) ReadConfig() {
	if !IsValidMode(lf.config.Loggers.LogFile.Mode) {
		lf.logger.Fatal("["+lf.name+"] logger=file - invalid mode: ", lf.config.Loggers.LogFile.Mode)
	}
	lf.fileDir = filepath.Dir(lf.config.Loggers.LogFile.FilePath)
	lf.fileName = filepath.Base(lf.config.Loggers.LogFile.FilePath)
	lf.fileExt = filepath.Ext(lf.fileName)
	lf.filePrefix = strings.TrimSuffix(lf.fileName, lf.fileExt)

	if len(lf.config.Loggers.LogFile.TextFormat) > 0 {
		lf.textFormat = strings.Fields(lf.config.Loggers.LogFile.TextFormat)
	} else {
		lf.textFormat = strings.Fields(lf.config.Global.TextFormat)
	}

	lf.LogInfo("running in mode: %s", lf.config.Loggers.LogFile.Mode)
}

func (lf *LogFile) ReloadConfig(config *pkgconfig.Config) {
	lf.LogInfo("reload configuration!")
	lf.configChan <- config
}

func (lf *LogFile) LogInfo(msg string, v ...interface{}) {
	lf.logger.Info("["+lf.name+"] logger=file - "+msg, v...)
}

func (lf *LogFile) LogError(msg string, v ...interface{}) {
	lf.logger.Error("["+lf.name+"] logger=file - "+msg, v...)
}

func (lf *LogFile) Stop() {
	lf.LogInfo("stopping routing handler...")
	lf.RoutingHandler.Stop()

	lf.LogInfo("stopping to run...")
	lf.stopRun <- true
	<-lf.doneRun

	lf.LogInfo("stopping to process...")
	lf.stopProcess <- true
	<-lf.doneProcess
}

func (lf *LogFile) Cleanup() error {
	if lf.config.Loggers.LogFile.MaxFiles == 0 {
		return nil
	}

	// remove old files ? keep only max files number
	entries, err := os.ReadDir(lf.fileDir)
	if err != nil {
		return err
	}

	logFiles := []int{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// extract timestamp from filename
		re := regexp.MustCompile(`^` + lf.filePrefix + `-(?P<ts>\d+)` + lf.fileExt)
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
	diffNB := len(logFiles) - lf.config.Loggers.LogFile.MaxFiles
	if diffNB > 0 {
		for i := 0; i < diffNB; i++ {
			filename := fmt.Sprintf("%s-%d%s", lf.filePrefix, logFiles[i], lf.fileExt)
			f := filepath.Join(lf.fileDir, filename)
			if _, err := os.Stat(f); os.IsNotExist(err) {
				f = filepath.Join(lf.fileDir, filename+compressSuffix)
			}

			// ignore errors on deletion
			os.Remove(f)
		}
	}

	return nil
}

func (lf *LogFile) OpenFile() error {

	fd, err := os.OpenFile(lf.config.Loggers.LogFile.FilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	lf.fileFd = fd

	fileinfo, err := os.Stat(lf.config.Loggers.LogFile.FilePath)
	if err != nil {
		return err
	}

	lf.fileSize = fileinfo.Size()

	switch lf.config.Loggers.LogFile.Mode {
	case pkgconfig.ModeText, pkgconfig.ModeJSON, pkgconfig.ModeFlatJSON:
		bufferSize := 4096
		lf.writerPlain = bufio.NewWriterSize(fd, bufferSize)

	case pkgconfig.ModePCAP:
		lf.writerPcap = pcapgo.NewWriter(fd)
		if lf.fileSize == 0 {
			if err := lf.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				return err
			}
		}

	case pkgconfig.ModeDNSTap:
		fsOptions := &framestream.EncoderOptions{ContentType: []byte("protobuf:dnstap.Dnstap"), Bidirectional: false}
		lf.writerDnstap, err = framestream.NewEncoder(fd, fsOptions)
		if err != nil {
			return err
		}

	}

	lf.LogInfo("file opened with success: %s", lf.config.Loggers.LogFile.FilePath)
	return nil
}

func (lf *LogFile) GetMaxSize() int64 {
	return int64(1024*1024) * int64(lf.config.Loggers.LogFile.MaxSize)
}

func (lf *LogFile) CompressFile() {
	entries, err := os.ReadDir(lf.fileDir)
	if err != nil {
		lf.LogError("unable to list all files: %s", err)
		return
	}

	for _, entry := range entries {
		// ignore folder
		if entry.IsDir() {
			continue
		}

		matched, _ := regexp.MatchString(`^`+lf.filePrefix+`-\d+`+lf.fileExt+`$`, entry.Name())
		if matched {
			src := filepath.Join(lf.fileDir, entry.Name())
			dst := filepath.Join(lf.fileDir, entry.Name()+compressSuffix)

			fd, err := os.Open(src)
			if err != nil {
				lf.LogError("compress - failed to open file: ", err)
				continue
			}
			defer fd.Close()

			fi, err := os.Stat(src)
			if err != nil {
				lf.LogError("compress - failed to stat file: ", err)
				continue
			}

			gzf, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
			if err != nil {
				lf.LogError("compress - failed to open compressed file: ", err)
				continue
			}
			defer gzf.Close()

			gz := gzip.NewWriter(gzf)

			if _, err := io.Copy(gz, fd); err != nil {
				lf.LogError("compress - failed to compress file: ", err)
				os.Remove(dst)
				continue
			}
			if err := gz.Close(); err != nil {
				lf.LogError("compress - failed to close gz writer: ", err)
				os.Remove(dst)
				continue
			}
			if err := gzf.Close(); err != nil {
				lf.LogError("compress - failed to close gz file: ", err)
				os.Remove(dst)
				continue
			}

			if err := fd.Close(); err != nil {
				lf.LogError("compress - failed to close log file: ", err)
				os.Remove(dst)
				continue
			}
			if err := os.Remove(src); err != nil {
				lf.LogError("compress - failed to remove log file: ", err)
				os.Remove(dst)
				continue
			}

			// post rotate command?
			lf.CompressPostRotateCommand(dst)
		}
	}

	lf.commpressTimer.Reset(time.Duration(lf.config.Loggers.LogFile.CompressInterval) * time.Second)
}

func (lf *LogFile) PostRotateCommand(filename string) {
	if len(lf.config.Loggers.LogFile.PostRotateCommand) > 0 {
		lf.LogInfo("execute postrotate command: %s", filename)
		_, err := exec.Command(lf.config.Loggers.LogFile.PostRotateCommand, filename).Output()
		if err != nil {
			lf.LogError("postrotate command error: %s", err)
		} else if lf.config.Loggers.LogFile.PostRotateDelete {
			os.Remove(filename)
		}
	}
}

func (lf *LogFile) CompressPostRotateCommand(filename string) {
	if len(lf.config.Loggers.LogFile.CompressPostCommand) > 0 {

		lf.LogInfo("execute compress postrotate command: %s", filename)
		_, err := exec.Command(lf.config.Loggers.LogFile.CompressPostCommand, filename).Output()
		if err != nil {
			lf.LogError("compress - postcommand error: %s", err)
		}
	}
}

func (lf *LogFile) FlushWriters() {
	switch lf.config.Loggers.LogFile.Mode {
	case pkgconfig.ModeText, pkgconfig.ModeJSON, pkgconfig.ModeFlatJSON:
		lf.writerPlain.Flush()
	case pkgconfig.ModeDNSTap:
		lf.writerDnstap.Flush()
	}
}

func (lf *LogFile) RotateFile() error {
	// close writer and existing file
	lf.FlushWriters()

	if lf.config.Loggers.LogFile.Mode == pkgconfig.ModeDNSTap {
		lf.writerDnstap.Close()
	}

	if err := lf.fileFd.Close(); err != nil {
		return err
	}

	// Rename current log file
	bfpath := filepath.Join(lf.fileDir, fmt.Sprintf("%s-%d%s", lf.filePrefix, time.Now().UnixNano(), lf.fileExt))
	err := os.Rename(lf.config.Loggers.LogFile.FilePath, bfpath)
	if err != nil {
		return err
	}

	// post rotate command?
	lf.PostRotateCommand(bfpath)

	// keep only max files
	err = lf.Cleanup()
	if err != nil {
		lf.LogError("unable to cleanup log files: %s", err)
		return err
	}

	// re-create new one
	if err := lf.OpenFile(); err != nil {
		lf.LogError("unable to re-create file: %s", err)
		return err
	}

	return nil
}

func (lf *LogFile) WriteToPcap(dm dnsutils.DNSMessage, pkt []gopacket.SerializableLayer) {
	// create the packet with the layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for _, layer := range pkt {
		layer.SerializeTo(buf, opts)
	}

	// rotate pcap file ?
	bufSize := len(buf.Bytes())

	if (lf.fileSize + int64(bufSize)) > lf.GetMaxSize() {
		if err := lf.RotateFile(); err != nil {
			lf.LogError("failed to rotate file: %s", err)
			return
		}
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec)),
		CaptureLength: bufSize,
		Length:        bufSize,
	}

	lf.writerPcap.WritePacket(ci, buf.Bytes())

	// increase size file
	lf.fileSize += int64(bufSize)
}

func (lf *LogFile) WriteToPlain(data []byte) {
	dataSize := int64(len(data))

	// rotate file ?
	if (lf.fileSize + dataSize) > lf.GetMaxSize() {
		if err := lf.RotateFile(); err != nil {
			lf.LogError("failed to rotate file: %s", err)
			return
		}
	}

	// write log to file
	n, _ := lf.writerPlain.Write(data)

	// increase size file
	lf.fileSize += int64(n)
}

func (lf *LogFile) WriteToDnstap(data []byte) {
	dataSize := int64(len(data))

	// rotate file ?
	if (lf.fileSize + dataSize) > lf.GetMaxSize() {
		if err := lf.RotateFile(); err != nil {
			lf.LogError("failed to rotate file: %s", err)
			return
		}
	}

	// write log to file
	n, _ := lf.writerDnstap.Write(data)

	// increase size file
	lf.fileSize += int64(n)
}

func (lf *LogFile) Run() {
	lf.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := lf.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := lf.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, lf.outputChan)
	subprocessors := transformers.NewTransforms(&lf.config.OutgoingTransformers, lf.logger, lf.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go lf.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-lf.stopRun:
			// cleanup transformers
			subprocessors.Reset()
			lf.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-lf.configChan:
			if !opened {
				return
			}
			lf.config = cfg
			lf.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-lf.inputChan:
			if !opened {
				lf.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				lf.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			lf.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			lf.outputChan <- dm
		}
	}
	lf.LogInfo("run terminated")
}

func (lf *LogFile) Process() {
	// prepare some timers
	flushInterval := time.Duration(lf.config.Loggers.LogFile.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)
	lf.commpressTimer = time.NewTimer(time.Duration(lf.config.Loggers.LogFile.CompressInterval) * time.Second)

	// nextStanzaBufferInterval := 10 * time.Second
	// nextStanzaBufferFull := time.NewTimer(nextStanzaBufferInterval)

	buffer := new(bytes.Buffer)
	var data []byte
	var err error

	lf.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-lf.stopProcess:
			// stop timer
			flushTimer.Stop()
			lf.commpressTimer.Stop()

			// flush writer
			lf.FlushWriters()

			// closing file
			lf.LogInfo("closing log file")
			if lf.config.Loggers.LogFile.Mode == pkgconfig.ModeDNSTap {
				lf.writerDnstap.Close()
			}
			lf.fileFd.Close()

			lf.doneProcess <- true
			break PROCESS_LOOP

		// case loggerName := <-lf.dropped:
		// 	if _, ok := lf.droppedCount[loggerName]; !ok {
		// 		lf.droppedCount[loggerName] = 1
		// 	} else {
		// 		lf.droppedCount[loggerName]++
		// 	}

		case dm, opened := <-lf.outputChan:
			if !opened {
				lf.LogInfo("output channel closed!")
				return
			}

			// write to file
			switch lf.config.Loggers.LogFile.Mode {

			// with basic text mode
			case pkgconfig.ModeText:
				lf.WriteToPlain(dm.Bytes(lf.textFormat,
					lf.config.Global.TextFormatDelimiter,
					lf.config.Global.TextFormatBoundary))

				var delimiter bytes.Buffer
				delimiter.WriteString("\n")
				lf.WriteToPlain(delimiter.Bytes())

			// with json mode
			case pkgconfig.ModeFlatJSON:
				flat, err := dm.Flatten()
				if err != nil {
					lf.LogError("flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				lf.WriteToPlain(buffer.Bytes())
				buffer.Reset()

			// with json mode
			case pkgconfig.ModeJSON:
				json.NewEncoder(buffer).Encode(dm)
				lf.WriteToPlain(buffer.Bytes())
				buffer.Reset()

			// with dnstap mode
			case pkgconfig.ModeDNSTap:
				data, err = dm.ToDNSTap()
				if err != nil {
					lf.LogError("failed to encode to DNStap protobuf: %s", err)
					continue
				}
				lf.WriteToDnstap(data)

			// with pcap mode
			case pkgconfig.ModePCAP:
				pkt, err := dm.ToPacketLayer()
				if err != nil {
					lf.LogError("failed to encode to packet layer: %s", err)
					continue
				}

				// write the packet
				lf.WriteToPcap(dm, pkt)
			}

		case <-flushTimer.C:
			// flush writer
			lf.FlushWriters()

			// reset flush timer and buffer
			buffer.Reset()
			flushTimer.Reset(flushInterval)

		case <-lf.commpressTimer.C:
			if lf.config.Loggers.LogFile.Compress {
				lf.CompressFile()
			}

			// case <-nextStanzaBufferFullf.C:
			// 	for v, k := range lf.droppedCount {
			// 		if k > 0 {
			// 			lf.LogError("stanza[%s] buffer is full, %d packet(s) dropped", v, k)
			// 			lf.droppedCount[v] = 0
			// 		}
			// 	}
			// 	nextStanzaBufferFullf.Reset(nextStanzaBufferInterval)

		}
	}
	lf.LogInfo("processing terminated")
}
