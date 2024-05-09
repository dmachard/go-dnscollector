package workers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type FalcoClient struct {
	*pkgutils.GenericWorker
}

func NewFalcoClient(config *pkgconfig.Config, console *logger.Logger, name string) *FalcoClient {
	w := &FalcoClient{GenericWorker: pkgutils.NewGenericWorker(config, console, name, "falco", config.Loggers.FalcoClient.ChannelBufferSize)}
	w.ReadConfig()
	return w
}

func (w *FalcoClient) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := pkgutils.GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := pkgutils.GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

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

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *FalcoClient) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	buffer := new(bytes.Buffer)

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// encode
			json.NewEncoder(buffer).Encode(dm)

			req, _ := http.NewRequest("POST", w.GetConfig().Loggers.FalcoClient.URL, buffer)
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			_, err := client.Do(req)
			if err != nil {
				w.LogError(err.Error())
			}

			// finally reset the buffer for next iter
			buffer.Reset()
		}
	}
}
