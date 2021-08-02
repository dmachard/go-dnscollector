package generators

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type LogFile struct {
	done       chan bool
	channel    chan dnsutils.DnsMessage
	writer     *bufio.Writer
	file       *os.File
	config     *dnsutils.Config
	logger     *logger.Logger
	size       int64
	fpath      string
	maxfiles   int
	maxsize    int
	logqueries bool
	logreplies bool
}

func NewLogFile(config *dnsutils.Config, logger *logger.Logger) *LogFile {
	logger.Info("generator logfile - enabled")
	o := &LogFile{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		config:  config,
		logger:  logger,
	}

	o.ReadConfig()

	if err := o.OpenFile(o.fpath); err != nil {
		o.logger.Fatal("generator logfile - unable to open output file:", err)
	}

	return o
}

func (c *LogFile) ReadConfig() {
	c.fpath = c.config.Generators.LogFile.FilePath
	c.maxfiles = c.config.Generators.LogFile.MaxFiles
	c.maxsize = c.config.Generators.LogFile.MaxSize
	c.logqueries = c.config.Generators.LogFile.LogQueries
	c.logreplies = c.config.Generators.LogFile.LogReplies

}

func (o *LogFile) OpenFile(fpath string) error {

	file, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	o.file = file

	fileinfo, err := os.Stat(fpath)
	if err != nil {
		return err
	}
	o.fpath = fpath
	o.size = fileinfo.Size()
	o.writer = bufio.NewWriter(file)

	return nil
}

func (o *LogFile) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *LogFile) MaxSize() int64 {
	return int64(1024*1024) * int64(o.maxsize)
}

func (o *LogFile) Write(d []byte) {
	write_len := int64(len(d))

	// rotate file ?
	if (o.size + write_len) > o.MaxSize() {
		if err := o.Rotate(); err != nil {
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
	o.logger.Info("generator logfile - stopping...")

	// close output channel
	close(o.channel)

	// close the file
	o.logger.Info("generator logfile - closing file")
	o.file.Close()

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *LogFile) Rotate() error {
	// Close existing file if open
	o.writer.Flush()
	if err := o.file.Close(); err != nil {
		return err
	}

	// Rename log file
	filedir := filepath.Dir(o.fpath)
	filename := filepath.Base(o.fpath)
	fileext := filepath.Ext(filename)
	fileprefix := filename[:len(filename)-len(fileext)]

	now := time.Now()
	timestamp := now.Unix()

	rfpath := filepath.Join(filedir, fmt.Sprintf("%s-%d%s", fileprefix, timestamp, fileext))

	err := os.Rename(o.fpath, rfpath)
	if err != nil {
		o.logger.Error("generator logfile - unable to rename file: %s", err)
	}

	// remove old files ?
	files, err := ioutil.ReadDir(filedir)
	if err != nil {
		o.logger.Error("generator logfile - unable to list log file: %s", err)
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
	diff_nb := len(logFiles) - o.maxfiles
	if diff_nb > 0 {
		for i := 0; i < diff_nb; i++ {
			f := filepath.Join(filedir, fmt.Sprintf("%s-%d%s", fileprefix, logFiles[i], fileext))
			err := os.Remove(f)
			if err != nil {
				o.logger.Error("generator logfile - unable to delete log file: %s", err)
			}

		}
	}

	// re-create the main log file.
	if err := o.OpenFile(o.fpath); err != nil {
		o.logger.Error("generator logfile - unable to re-create output file: %s", err)
	}

	return nil
}

func (o *LogFile) Run() {
	o.logger.Info("generator logfile - running in background...")

	tflush_interval := 5 * time.Second
	tflush := time.NewTimer(tflush_interval)
LOOP:
	for {
		select {
		case dm, opened := <-o.channel:
			if !opened {
				o.logger.Info("generator logfile - channel closed")
				break LOOP
			}

			if dm.Type == "query" && !o.logqueries {
				continue
			}
			if dm.Type == "reply" && !o.logreplies {
				continue
			}

			// write to file
			o.Write(dm.Bytes())
		case <-tflush.C:
			o.writer.Flush()
			tflush.Reset(tflush_interval)
		}
	}

	// stop and flush
	tflush.Stop()
	o.writer.Flush()

	o.logger.Info("generator logfile - run terminated")

	// the job is done
	o.done <- true
}
