package loggers

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
)

const (
	compressSuffix = ".gz"
)

type LogFile struct {
	done           chan bool
	channel        chan dnsutils.DnsMessage
	writer         *bufio.Writer
	file           *os.File
	config         *dnsutils.Config
	logger         *logger.Logger
	size           int64
	filedir        string
	filename       string
	fileext        string
	fileprefix     string
	commpressTimer *time.Timer
	textFormat     []string
}

func NewLogFile(config *dnsutils.Config, logger *logger.Logger) *LogFile {
	logger.Info("logger logfile - enabled")
	o := &LogFile{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		config:  config,
		logger:  logger,
	}

	o.ReadConfig()

	if err := o.OpenFile(); err != nil {
		o.logger.Fatal("logger logfile - unable to open output file:", err)
	}

	return o
}

func (c *LogFile) ReadConfig() {
	c.filedir = filepath.Dir(c.config.Loggers.LogFile.FilePath)
	c.filename = filepath.Base(c.config.Loggers.LogFile.FilePath)
	c.fileext = filepath.Ext(c.filename)
	c.fileprefix = strings.TrimSuffix(c.filename, c.fileext)

	if len(c.config.Loggers.LogFile.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.LogFile.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Subprocessors.TextFormat)
	}
}

func (c *LogFile) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("logger to file - "+msg, v...)
}

func (c *LogFile) LogError(msg string, v ...interface{}) {
	c.logger.Error("logger to file - "+msg, v...)
}

func (o *LogFile) OpenFile() error {

	file, err := os.OpenFile(o.config.Loggers.LogFile.FilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	o.file = file

	fileinfo, err := os.Stat(o.config.Loggers.LogFile.FilePath)
	if err != nil {
		return err
	}
	//o.fpath = fpath
	o.size = fileinfo.Size()
	o.writer = bufio.NewWriter(file)

	return nil
}

func (o *LogFile) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *LogFile) MaxSize() int64 {
	return int64(1024*1024) * int64(o.config.Loggers.LogFile.MaxSize)
}

func (o *LogFile) Write(d []byte) {
	write_len := int64(len(d))

	// rotate file ?

	if (o.size + write_len) > o.MaxSize() {
		if err := o.Rotate(); err != nil {
			o.LogError("failed to rotate file: %s", err)
			return
		}
	}

	// write log to file
	n, _ := o.writer.Write(d)

	// increase size file
	o.size += int64(n)

}

func (o *LogFile) Flush() {
	o.writer.Flush()
}

func (o *LogFile) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	close(o.channel)

	// close the file
	o.LogInfo("closing file")
	o.file.Close()

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *LogFile) Cleanup() error {
	if o.config.Loggers.LogFile.MaxFiles == 0 {
		return nil
	}

	// keep only max files number
	files, err := ioutil.ReadDir(o.filedir)
	if err != nil {
		return err
	}

	logFiles := []int{}
	for _, f := range files {
		// ignore folder
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
	diff_nb := len(logFiles) - o.config.Loggers.LogFile.MaxFiles
	if diff_nb > 0 {
		for i := 0; i < diff_nb; i++ {

			filename := fmt.Sprintf("%s-%d%s", o.fileprefix, logFiles[i], o.fileext)
			f := filepath.Join(o.filedir, filename)
			if _, err := os.Stat(f); os.IsNotExist(err) {
				f = filepath.Join(o.filedir, filename+compressSuffix)
			}

			// ignore errors on deletion
			os.Remove(f)
		}
	}

	return nil
}

func (o *LogFile) Compress() {
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
				o.LogError("compress - failed to open log file: ", err)
				continue
			}
			defer fl.Close()

			fi, err := os.Stat(src)
			if err != nil {
				o.LogError("compress - failed to stat log file: ", err)
				continue
			}

			gzf, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
			if err != nil {
				o.LogError("compress - failed to open compressed log file: ", err)
				continue
			}
			defer gzf.Close()

			gz := gzip.NewWriter(gzf)

			if _, err := io.Copy(gz, fl); err != nil {
				o.LogError("compress - failed to compress log file: ", err)
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
				o.LogError("compress - failed to close log file: ", err)
				os.Remove(dst)
				continue
			}
			if err := os.Remove(src); err != nil {
				o.LogError("compress - failed to remove log file: ", err)
				os.Remove(dst)
				continue
			}

		}
	}

	o.commpressTimer.Reset(time.Duration(o.config.Loggers.LogFile.CompressInterval) * time.Second)
}

func (o *LogFile) PostRotateCommand(filename string) {
	if len(o.config.Loggers.LogFile.PostRotateCommand) > 0 {
		out, err := exec.Command(o.config.Loggers.LogFile.PostRotateCommand, filename).Output()
		if err != nil {
			o.LogError("postrotate command error: %s", err)
			o.LogError("postrotate output: %s", out)
		} else {
			if o.config.Loggers.LogFile.PostRotateDelete {
				os.Remove(filename)
			}
		}
	}
}

func (o *LogFile) Rotate() error {
	// close existing file
	o.writer.Flush()
	if err := o.file.Close(); err != nil {
		return err
	}

	// Rename current log file
	bfpath := filepath.Join(o.filedir, fmt.Sprintf("%s-%d%s", o.fileprefix, time.Now().UnixNano(), o.fileext))
	err := os.Rename(o.config.Loggers.LogFile.FilePath, bfpath)
	if err != nil {
		return err
	}

	// post rotate command?
	o.PostRotateCommand(bfpath)

	// keep only max files
	err = o.Cleanup()
	if err != nil {
		o.LogError("unable to cleanup log files: %s", err)
		return err
	}

	// re-create new one
	if err := o.OpenFile(); err != nil {
		return err
	}

	return nil
}

func (o *LogFile) Run() {
	o.LogInfo("running in background...")

	tflush_interval := time.Duration(o.config.Loggers.LogFile.FlushInterval) * time.Second
	tflush := time.NewTimer(tflush_interval)
	o.commpressTimer = time.NewTimer(time.Duration(o.config.Loggers.LogFile.CompressInterval) * time.Second)

	buffer := new(bytes.Buffer)
LOOP:
	for {
		select {
		case dm, opened := <-o.channel:
			if !opened {
				o.LogInfo("channel closed")
				break LOOP
			}

			// write to file
			switch o.config.Loggers.LogFile.Mode {
			case "text":
				o.Write(dm.Bytes(o.textFormat))
			case "json":
				json.NewEncoder(buffer).Encode(dm)
				o.Write(buffer.Bytes())
				buffer.Reset()
			}

		case <-tflush.C:
			o.writer.Flush()
			tflush.Reset(tflush_interval)
			buffer.Reset()

		case <-o.commpressTimer.C:
			if o.config.Loggers.LogFile.Compress {
				o.Compress()
			}

		}
	}

	// stop and flush
	tflush.Stop()
	o.writer.Flush()

	o.LogInfo("run terminated")

	// the job is done
	o.done <- true
}
