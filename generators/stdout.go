package generators

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

type StdOut struct {
	done    chan bool
	channel chan dnsmessage.DnsMessage
	logger  *logger.Logger
}

func NewStdOut(config *common.Config, logger *logger.Logger) *StdOut {
	logger.Info("generator stdout - enabled")
	o := &StdOut{
		done:    make(chan bool),
		channel: make(chan dnsmessage.DnsMessage, 512),
		logger:  logger,
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
		fmt.Print(string(line))
	}
	o.logger.Info("generator stdout - run terminated")

	// the job is done
	o.done <- true
}
