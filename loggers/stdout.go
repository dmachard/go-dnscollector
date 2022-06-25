package loggers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type StdOut struct {
	done       chan bool
	channel    chan dnsutils.DnsMessage
	textFormat []string
	config     *dnsutils.Config
	logger     *logger.Logger
	stdout     *log.Logger
	name       string
}

func NewStdOut(config *dnsutils.Config, console *logger.Logger, name string) *StdOut {
	console.Info("[%s] logger stdout - enabled", name)
	o := &StdOut{
		done:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  console,
		config:  config,
		stdout:  log.New(os.Stdout, "", 0),
		name:    name,
	}
	o.ReadConfig()
	return o
}

func (c *StdOut) ReadConfig() {
	if len(c.config.Loggers.Stdout.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.Stdout.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}
}

func (c *StdOut) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger to stdout - "+msg, v...)
}

func (c *StdOut) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger to stdout - "+msg, v...)
}

func (o *StdOut) SetBuffer(b *bytes.Buffer) {
	o.stdout.SetOutput(b)
}

func (o *StdOut) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *StdOut) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *StdOut) Run() {
	o.LogInfo("running in background...")

	buffer := new(bytes.Buffer)
	for dm := range o.channel {
		switch o.config.Loggers.Stdout.Mode {
		case "text":
			o.stdout.Print(dm.String(o.textFormat))
		case "json":
			json.NewEncoder(buffer).Encode(dm)
			fmt.Print(buffer.String())
			buffer.Reset()
		}
	}
	o.LogInfo("run terminated")

	// the job is done
	o.done <- true
}
