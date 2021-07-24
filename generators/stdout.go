package generators

import (
	"bytes"
	"log"
	"os"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

type StdOut struct {
	done    chan bool
	channel chan dnsmessage.DnsMessage
	logger  *logger.Logger
	stdout  *log.Logger
}

func NewStdOut(config *common.Config, console *logger.Logger) *StdOut {
	console.Info("generator stdout - enabled")
	o := &StdOut{
		done:    make(chan bool),
		channel: make(chan dnsmessage.DnsMessage, 512),
		logger:  console,
		stdout:  log.New(os.Stdout, "", 0),
	}
	return o
}

func (o *StdOut) SetBuffer(b *bytes.Buffer) {
	o.stdout.SetOutput(b)
}

func (o *StdOut) Channel() chan dnsmessage.DnsMessage {
	return o.channel
}

func (o *StdOut) Print(dm dnsmessage.DnsMessage) {
	o.stdout.Print(dm.String())
}

func (o *StdOut) Stop() {
	o.logger.Info("generator stdout - stopping...")

	// close output channel
	o.logger.Info("generator stdout - closing channel")
	close(o.channel)

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *StdOut) Run() {
	o.logger.Info("generator stdout - running in background...")

	for dm := range o.channel {
		o.Print(dm)
	}
	o.logger.Info("generator stdout - run terminated")

	// the job is done
	o.done <- true
}
