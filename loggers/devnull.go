package loggers

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type DevNull struct {
	*pkgutils.GenericWorker
}

func NewDevNull(config *pkgconfig.Config, console *logger.Logger, name string) *DevNull {
	s := &DevNull{GenericWorker: pkgutils.NewGenericWorker(config, console, name, "devnull", config.Loggers.DevNull.ChannelBufferSize)}
	s.ReadConfig()
	return s
}

func (w *DevNull) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()

		case _, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("run: input channel closed!")
				return
			}
		}
	}
}

func (w *DevNull) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		case _, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("process: output channel closed!")
				return
			}

		}
	}
}
