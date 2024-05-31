package workers

import (
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type DevNull struct {
	*GenericWorker
}

func NewDevNull(config *pkgconfig.Config, console *logger.Logger, name string) *DevNull {
	s := &DevNull{GenericWorker: NewGenericWorker(config, console, name, "devnull", config.Loggers.DevNull.ChannelBufferSize, pkgconfig.DefaultMonitor)}
	s.ReadConfig()
	return s
}

func (w *DevNull) StartCollect() {
	w.LogInfo("starting data collection")
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
	w.LogInfo("logging has started")
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
