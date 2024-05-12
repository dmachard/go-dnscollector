package workers

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"

	"net/http"
	"net/url"
)

type ElasticSearchClient struct {
	*pkgutils.GenericWorker
	server, index, bulkURL string
	httpClient             *http.Client
}

func NewElasticSearchClient(config *pkgconfig.Config, console *logger.Logger, name string) *ElasticSearchClient {
	w := &ElasticSearchClient{GenericWorker: pkgutils.NewGenericWorker(config, console, name, "elasticsearch", config.Loggers.ElasticSearchClient.ChannelBufferSize)}
	w.ReadConfig()
	w.httpClient = &http.Client{Timeout: 5 * time.Second}
	return w
}

func (w *ElasticSearchClient) ReadConfig() {

	if w.GetConfig().Loggers.ElasticSearchClient.Compression != pkgconfig.CompressNone {
		w.LogInfo(w.GetConfig().Loggers.ElasticSearchClient.Compression)
		switch w.GetConfig().Loggers.ElasticSearchClient.Compression {
		case pkgconfig.CompressGzip:
			w.LogInfo("gzip compression is enabled")
		default:
			w.LogFatal(pkgutils.PrefixLogWorker+"["+w.GetName()+"] elasticsearch - invalid compress mode: ", w.GetConfig().Loggers.ElasticSearchClient.Compression)
		}
	}

	w.server = w.GetConfig().Loggers.ElasticSearchClient.Server
	w.index = w.GetConfig().Loggers.ElasticSearchClient.Index

	u, err := url.Parse(w.server)
	if err != nil {
		w.LogError(err.Error())
	}
	u.Path = path.Join(u.Path, w.index, "_bulk")
	w.bulkURL = u.String()
}

func (w *ElasticSearchClient) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := pkgutils.GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := pkgutils.GetRoutes(w.GetDroppedRoutes())

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

func (w *ElasticSearchClient) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	// create a new encoder that writes to the buffer
	buffer := bytes.NewBuffer(make([]byte, 0, w.GetConfig().Loggers.ElasticSearchClient.BulkSize))
	encoder := json.NewEncoder(buffer)

	flushInterval := time.Duration(w.GetConfig().Loggers.ElasticSearchClient.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	dataBuffer := make(chan []byte, w.GetConfig().Loggers.ElasticSearchClient.BulkChannelSize)
	go func() {
		for data := range dataBuffer {
			var err error
			if w.GetConfig().Loggers.ElasticSearchClient.Compression == pkgconfig.CompressGzip {
				err = w.sendCompressedBulk(data)
			} else {
				err = w.sendBulk(data)
			}
			if err != nil {
				w.LogError("error sending bulk data: %v", err)
			}
		}
	}()

	for {
		select {
		case <-w.OnLoggerStopped():
			close(dataBuffer)
			return

			// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// append dns message to buffer
			flat, err := dm.Flatten()
			if err != nil {
				w.LogError("flattening DNS message failed: %e", err)
			}
			buffer.WriteString("{ \"create\" : {}}\n")
			encoder.Encode(flat)

			// Send data and reset buffer
			if buffer.Len() >= w.GetConfig().Loggers.ElasticSearchClient.BulkSize {
				bufCopy := make([]byte, buffer.Len())
				buffer.Read(bufCopy)
				buffer.Reset()

				select {
				case dataBuffer <- bufCopy:
				default:
					w.LogError("Send buffer is full, bulk dropped")
				}
			}

		// flush the buffer every ?
		case <-flushTimer.C:

			// Send data and reset buffer
			if buffer.Len() > 0 {
				bufCopy := make([]byte, buffer.Len())
				buffer.Read(bufCopy)
				buffer.Reset()

				select {
				case dataBuffer <- bufCopy:
				default:
					w.LogError("automatic flush, send buffer is full, bulk dropped")
				}
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
}

func (w *ElasticSearchClient) sendBulk(bulk []byte) error {
	// Create a new HTTP request
	req, err := http.NewRequest("POST", w.bulkURL, bytes.NewReader(bulk))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request using the HTTP client
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (w *ElasticSearchClient) sendCompressedBulk(bulk []byte) error {
	var compressedBulk bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBulk)

	// Write the uncompressed data to the gzip writer
	_, err := gzipWriter.Write(bulk)
	if err != nil {
		fmt.Println("gzip", err)
		return err
	}

	// Close the gzip writer to flush any remaining data
	err = gzipWriter.Close()
	if err != nil {
		return err
	}

	// Create a new HTTP request
	req, err := http.NewRequest("POST", w.bulkURL, &compressedBulk)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip") // Set Content-Encoding header to gzip

	// Send the request using the HTTP client
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
