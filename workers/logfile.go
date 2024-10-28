package workers

import (
	"bufio"
	"bytes"
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

	"github.com/klauspost/compress/gzip"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
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

func IsValid(mode string) bool {
	switch mode {
	case
		pkgconfig.ModeJinja,
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
	*GenericWorker
	writerPlain                            *bufio.Writer
	writerPcap                             *pcapgo.Writer
	writerDnstap                           *framestream.Encoder
	fileFd                                 *os.File
	fileSize                               int64
	fileDir, fileName, fileExt, filePrefix string
	textFormat                             []string
	compressQueue                          chan string
	commandQueue                           chan string
}

func NewLogFile(config *pkgconfig.Config, logger *logger.Logger, name string) *LogFile {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Loggers.LogFile.ChannelBufferSize > 0 {
		bufSize = config.Loggers.LogFile.ChannelBufferSize
	}
	w := &LogFile{
		GenericWorker: NewGenericWorker(config, logger, name, "file", bufSize, pkgconfig.DefaultMonitor),
		compressQueue: make(chan string, 1),
		commandQueue:  make(chan string, 1),
	}
	w.ReadConfig()
	if err := w.OpenCurrentFile(); err != nil {
		w.LogFatal(pkgconfig.PrefixLogWorker+"["+name+"] file - unable to open output file:", err)
	}

	// start compressor
	go w.startCompressor()
	w.initializeCompressionQueue()

	// start post command processor
	go w.startCommandProcessor()

	return w
}

func (w *LogFile) ReadConfig() {
	if !IsValid(w.GetConfig().Loggers.LogFile.Mode) {
		w.LogFatal("["+w.GetName()+"] logger=file - invalid mode: ", w.GetConfig().Loggers.LogFile.Mode)
	}
	w.fileDir = filepath.Dir(w.GetConfig().Loggers.LogFile.FilePath)
	w.fileName = filepath.Base(w.GetConfig().Loggers.LogFile.FilePath)
	w.fileExt = filepath.Ext(w.fileName)
	w.filePrefix = strings.TrimSuffix(w.fileName, w.fileExt)

	if len(w.GetConfig().Loggers.LogFile.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.LogFile.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	w.LogInfo("running in mode: %s", w.GetConfig().Loggers.LogFile.Mode)
}

func (w *LogFile) RemoveOldFiles() error {
	if w.GetConfig().Loggers.LogFile.MaxFiles == 0 {
		return nil
	}

	// remove old files ? keep only max files number
	entries, err := os.ReadDir(w.fileDir)
	if err != nil {
		return err
	}

	logFiles := []int{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// extract timestamp from filename
		re := regexp.MustCompile(`^` + w.filePrefix + `-(?P<ts>\d+)` + w.fileExt)
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
	diffNB := len(logFiles) - (w.GetConfig().Loggers.LogFile.MaxFiles - 1)
	if diffNB > 0 {
		for i := 0; i < diffNB; i++ {
			filename := fmt.Sprintf("%s-%d%s", w.filePrefix, logFiles[i], w.fileExt)
			f := filepath.Join(w.fileDir, filename)
			if _, err := os.Stat(f); os.IsNotExist(err) {
				f = filepath.Join(w.fileDir, filename+compressSuffix)
			}

			// ignore errors on deletion
			os.Remove(f)
		}
	}

	return nil
}

func (w *LogFile) OpenCurrentFile() error {
	w.LogInfo("create new log file: %s", w.GetConfig().Loggers.LogFile.FilePath)

	fd, err := os.OpenFile(w.GetConfig().Loggers.LogFile.FilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	w.fileFd = fd

	fileinfo, err := os.Stat(w.GetConfig().Loggers.LogFile.FilePath)
	if err != nil {
		return err
	}

	w.fileSize = fileinfo.Size()

	switch w.GetConfig().Loggers.LogFile.Mode {
	case pkgconfig.ModeText, pkgconfig.ModeJSON, pkgconfig.ModeFlatJSON:
		w.writerPlain = bufio.NewWriterSize(fd, w.config.Loggers.LogFile.MaxBatchSize)

	case pkgconfig.ModePCAP:
		w.writerPcap = pcapgo.NewWriter(fd)
		if w.fileSize == 0 {
			if err := w.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				return err
			}
		}

	case pkgconfig.ModeDNSTap:
		fsOptions := &framestream.EncoderOptions{ContentType: []byte("protobuf:dnstap.Dnstap"), Bidirectional: false}
		w.writerDnstap, err = framestream.NewEncoder(fd, fsOptions)
		if err != nil {
			return err
		}

	}

	w.LogInfo("new log file created")
	return nil
}

func (w *LogFile) GetMaxSize() int64 {
	return int64(1024*1024) * int64(w.GetConfig().Loggers.LogFile.MaxSize)
}

func (w *LogFile) compressFile(filename string) {
	w.LogInfo("start to compress in background: %s", filename)

	// prepare dest filename
	baseName := filepath.Base(filename)
	baseName = strings.TrimPrefix(baseName, "tocompress-")
	if len(w.config.Loggers.LogFile.PostRotateCommand) > 0 {
		baseName = "toprocess-" + baseName
	}
	tmpFile := filename + compressSuffix
	dstFile := filepath.Join(filepath.Dir(filename), baseName+compressSuffix)

	// open the file
	fd, err := os.Open(filename)
	if err != nil {
		w.LogError("compress - failed to open file: %s", err)
		return
	}
	defer fd.Close()

	fi, err := os.Stat(filename)
	if err != nil {
		w.LogError("compress - failed to stat file: %s", err)
		return
	}

	gzf, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
	if err != nil {
		w.LogError("compress - failed to open compressed file: %s", err)
		return
	}
	defer gzf.Close()

	gz := gzip.NewWriter(gzf)

	if _, err := io.Copy(gz, fd); err != nil {
		w.LogError("compress - failed to compress file: %s", err)
		os.Remove(tmpFile)
		return
	}
	if err := gz.Close(); err != nil {
		w.LogError("compress - failed to close gz writer: %s", err)
		os.Remove(tmpFile)
		return
	}
	if err := gzf.Close(); err != nil {
		w.LogError("compress - failed to close gz file: %s", err)
		os.Remove(tmpFile)
		return
	}

	if err := fd.Close(); err != nil {
		w.LogError("compress - failed to close log file: %s", err)
		os.Remove(tmpFile)
		return
	}
	if err := os.Remove(filename); err != nil {
		w.LogError("compress - failed to remove log file: %s", err)
		os.Remove(tmpFile)
		return
	}

	// finally rename the gzip file
	if err := os.Rename(tmpFile, dstFile); err != nil {
		w.LogError("compress - unable to rename file: %s", err)
		os.Remove(tmpFile)
		return
	}

	// run post command on compressed file ?
	if len(w.config.Loggers.LogFile.PostRotateCommand) > 0 {
		go func() {
			w.commandQueue <- dstFile
		}()
	}

	w.LogInfo("compression terminated - %s", dstFile)
}

func (w *LogFile) postRotateCommand(fullPath string) {
	if len(w.GetConfig().Loggers.LogFile.PostRotateCommand) > 0 {
		w.LogInfo("execute postrotate command: %s", fullPath)
		dir := filepath.Dir(fullPath)
		filename := filepath.Base(fullPath)
		baseName := strings.TrimPrefix(filename, "toprocess-")
		_, err := exec.Command(w.GetConfig().Loggers.LogFile.PostRotateCommand, fullPath, dir, baseName).Output()
		if err != nil {
			w.LogError("postrotate command error - %s - %s", filename, err)
		} else {
			w.LogInfo("postrotate command terminated - %s", filename)
		}

		if w.GetConfig().Loggers.LogFile.PostRotateDelete {
			w.LogInfo("postrotate command delete original file - %s", filename)
			os.Remove(filename)
		}
	}
}

func (w *LogFile) FlushWriters() {
	switch w.GetConfig().Loggers.LogFile.Mode {
	case pkgconfig.ModeText, pkgconfig.ModeJSON, pkgconfig.ModeFlatJSON:
		w.writerPlain.Flush()
	case pkgconfig.ModeDNSTap:
		w.writerDnstap.Flush()
	}
}

func (w *LogFile) RotateFile() error {
	// close writer and existing file
	w.FlushWriters()

	if w.GetConfig().Loggers.LogFile.Mode == pkgconfig.ModeDNSTap {
		w.writerDnstap.Close()
	}

	if err := w.fileFd.Close(); err != nil {
		return err
	}

	// Rename current log file
	newFilename := fmt.Sprintf("%s-%d%s", w.filePrefix, time.Now().UnixNano(), w.fileExt)
	if w.config.Loggers.LogFile.Compress {
		newFilename = fmt.Sprintf("tocompress-%s", newFilename)
	} else if len(w.config.Loggers.LogFile.PostRotateCommand) > 0 {
		newFilename = fmt.Sprintf("toprocess-%s", newFilename)
	}
	bfpath := filepath.Join(w.fileDir, newFilename)
	err := os.Rename(w.GetConfig().Loggers.LogFile.FilePath, bfpath)
	if err != nil {
		return err
	}

	// post rotate command?
	if w.config.Loggers.LogFile.Compress {
		go func() {
			w.compressQueue <- bfpath
		}()
	} else {
		go func() {
			w.commandQueue <- bfpath
		}()
	}

	// keep only max files
	err = w.RemoveOldFiles()
	if err != nil {
		w.LogError("unable to cleanup log files: %s", err)
		return err
	}

	// re-create new one
	if err := w.OpenCurrentFile(); err != nil {
		w.LogError("unable to re-create file: %s", err)
		return err
	}

	return nil
}

func (w *LogFile) WriteToPcap(dm dnsutils.DNSMessage, pkt []gopacket.SerializableLayer) {
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

	if (w.fileSize + int64(bufSize)) > w.GetMaxSize() {
		if err := w.RotateFile(); err != nil {
			w.LogError("failed to rotate file: %s", err)
			return
		}
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec)),
		CaptureLength: bufSize,
		Length:        bufSize,
	}

	w.writerPcap.WritePacket(ci, buf.Bytes())

	// increase size file
	w.fileSize += int64(bufSize)
}

func (w *LogFile) WriteToPlain(data []byte) {
	dataSize := int64(len(data))

	// rotate file ?
	if (w.fileSize + dataSize) > w.GetMaxSize() {
		if err := w.RotateFile(); err != nil {
			w.LogError("failed to rotate file: %s", err)
			return
		}
	}

	// write log to file
	n, _ := w.writerPlain.Write(data)

	// increase size file
	w.fileSize += int64(n)
}

func (w *LogFile) WriteToDnstap(data []byte) {
	dataSize := int64(len(data))

	// rotate file ?
	if (w.fileSize + dataSize) > w.GetMaxSize() {
		if err := w.RotateFile(); err != nil {
			w.LogError("failed to rotate file: %s", err)
			return
		}
	}

	// write log to file
	n, _ := w.writerDnstap.Write(data)

	// increase size file
	w.fileSize += int64(n)
}

func (w *LogFile) initializeCompressionQueue() {
	// Get all files in the log directory
	files, err := os.ReadDir(w.fileDir)
	if err != nil {
		w.LogError("error reading log directory: %v", err)
		return
	}

	// Find files that start with "tocompress-"
	for _, file := range files {
		fileName := file.Name()

		// Check if the file is both marked for compression and has a `.gz` suffix
		if strings.HasPrefix(fileName, "tocompress-") && strings.HasSuffix(fileName, ".gz") {
			// Build the full path of the file
			fullPath := filepath.Join(w.fileDir, fileName)

			// Attempt to remove incomplete .gz file
			if err := os.Remove(fullPath); err != nil {
				w.LogError("error deleting incomplete compressed file %s: %v", fileName, err)
			}
			continue
		}

		// If it's a pending compression file, add it to the compression queue
		if strings.HasPrefix(fileName, "tocompress-") && !strings.HasSuffix(fileName, ".gz") {
			fullPath := filepath.Join(w.fileDir, fileName)
			w.compressQueue <- fullPath
		}
	}
}

func (w *LogFile) startCompressor() {
	for filename := range w.compressQueue {
		w.compressFile(filename)
	}
}

func (w *LogFile) startCommandProcessor() {
	for filename := range w.commandQueue {
		w.postRotateCommand(filename)
	}
}

func (w *LogFile) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

			// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}

			// count global messages
			w.CountIngressTraffic()

			// apply tranforms, init dns message with additionnals parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.CountEgressTraffic()

			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *LogFile) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// prepare some timers
	flushInterval := time.Duration(w.GetConfig().Loggers.LogFile.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	buffer := new(bytes.Buffer)
	var data []byte
	var err error

	// Max size of a batch before forcing a write
	batch := new(bytes.Buffer)
	maxBatchSize := w.config.Loggers.LogFile.MaxBatchSize
	batchSize := 0 // Current batch size

	for {
		select {
		case <-w.OnLoggerStopped():
			// close channels
			close(w.compressQueue)
			close(w.commandQueue)

			// stop timer
			flushTimer.Stop()

			// Force write remaining batch data
			if batchSize > 0 {
				w.WriteToPlain(batch.Bytes())
			}

			// flush writer
			w.FlushWriters()

			// closing file
			w.LogInfo("closing log file")
			if w.GetConfig().Loggers.LogFile.Mode == pkgconfig.ModeDNSTap {
				w.writerDnstap.Close()
			}
			w.fileFd.Close()

			return

		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// Process the message based on the configured mode
			var message []byte
			switch w.GetConfig().Loggers.LogFile.Mode {

			// with basic text mode
			case pkgconfig.ModeText:
				message = dm.Bytes(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
				batch.Write(message)
				batch.WriteString("\n")

			// with custom text mode
			case pkgconfig.ModeJinja:
				textLine, err := dm.ToTextTemplate(w.GetConfig().Global.TextJinja)
				if err != nil {
					w.LogError("jinja template: %s", err)
					continue
				}
				batch.Write([]byte(textLine))

			// with json mode
			case pkgconfig.ModeFlatJSON:
				flat, err := dm.Flatten()
				if err != nil {
					w.LogError("flattening DNS message failed: %e", err)
					continue
				}
				json.NewEncoder(buffer).Encode(flat)
				w.WriteToPlain(buffer.Bytes())
				buffer.Reset()

			// with json mode
			case pkgconfig.ModeJSON:
				json.NewEncoder(buffer).Encode(dm)
				batch.Write(buffer.Bytes())
				buffer.Reset()

			// with dnstap mode
			case pkgconfig.ModeDNSTap:
				data, err = dm.ToDNSTap(w.GetConfig().Loggers.LogFile.ExtendedSupport)
				if err != nil {
					w.LogError("failed to encode to DNStap protobuf: %s", err)
					continue
				}
				w.WriteToDnstap(data)

			// with pcap mode
			case pkgconfig.ModePCAP:
				pkt, err := dm.ToPacketLayer()
				if err != nil {
					w.LogError("failed to encode to packet layer: %s", err)
					continue
				}

				// write the packet
				w.WriteToPcap(dm, pkt)
			}

			// Update the batch size
			batchSize += batch.Len()

			// If the batch exceeds the max size, force a write
			if batchSize >= maxBatchSize {
				w.WriteToPlain(batch.Bytes())
				batch.Reset() // Reset batch after write
				batchSize = 0
			}

		case <-flushTimer.C:
			// Flush the current batch, then flush the writers
			if batchSize > 0 {
				w.WriteToPlain(batch.Bytes())
				batch.Reset()
				batchSize = 0
			}

			// flush writer
			w.FlushWriters()

			// reset flush timer and buffer
			buffer.Reset()
			flushTimer.Reset(flushInterval)

		}
	}
}
