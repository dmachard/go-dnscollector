package generators

import (
	"log"
	"os"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

type StdOut struct {
	done         chan bool
	channel      chan dnsmessage.DnsMessage
	logger       *logger.Logger
	stdoutLogger *log.Logger
	testing      bool
}

func NewStdOut(config *common.Config, console *logger.Logger) *StdOut {
	console.Info("generator stdout - enabled")
	o := &StdOut{
		done:         make(chan bool),
		channel:      make(chan dnsmessage.DnsMessage, 512),
		logger:       console,
		stdoutLogger: log.New(os.Stdout, "", 0),
		testing:      false,
	}
	return o
}

func (o *StdOut) Channel() chan dnsmessage.DnsMessage {
	return o.channel
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
		line := dnsmessage.TransformToText(dm)
		o.stdoutLogger.Print(string(line))

		// run only once if testing mode is enabled
		if o.testing {
			break
		}
	}
	o.logger.Info("generator stdout - run terminated")

	// the job is done
	if !o.testing {
		o.done <- true
	}
}
