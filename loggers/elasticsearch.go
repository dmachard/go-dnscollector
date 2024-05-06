package loggers

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"

	"net/http"
	"net/url"
)

type ElasticSearchClient struct {
	stopProcess, doneProcess chan bool
	stopRun, doneRun         chan bool
	inputChan, outputChan    chan dnsutils.DNSMessage
	config                   *pkgconfig.Config
	configChan               chan *pkgconfig.Config
	logger                   *logger.Logger
	name                     string
	server, index, bulkURL   string
	RoutingHandler           pkgutils.RoutingHandler
	httpClient               *http.Client
}

func NewElasticSearchClient(config *pkgconfig.Config, console *logger.Logger, name string) *ElasticSearchClient {
	console.Info(pkgutils.PrefixLogLogger+"[%s] elasticsearch - enabled", name)
	ec := &ElasticSearchClient{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.ElasticSearchClient.ChannelBufferSize),
		logger:         console,
		config:         config,
		configChan:     make(chan *pkgconfig.Config),
		name:           name,
		RoutingHandler: pkgutils.NewRoutingHandler(config, console, name),
	}
	ec.ReadConfig()

	ec.httpClient = &http.Client{
		Timeout: 5 * time.Second,
	}

	return ec
}

func (ec *ElasticSearchClient) GetName() string { return ec.name }

func (ec *ElasticSearchClient) AddDroppedRoute(wrk pkgutils.Worker) {
	ec.RoutingHandler.AddDroppedRoute(wrk)
}

func (ec *ElasticSearchClient) AddDefaultRoute(wrk pkgutils.Worker) {
	ec.RoutingHandler.AddDefaultRoute(wrk)
}

func (ec *ElasticSearchClient) SetLoggers(loggers []pkgutils.Worker) {}

func (ec *ElasticSearchClient) ReadConfig() {

	if ec.config.Loggers.ElasticSearchClient.Compression != pkgconfig.CompressNone {
		ec.LogInfo(ec.config.Loggers.ElasticSearchClient.Compression)
		switch ec.config.Loggers.ElasticSearchClient.Compression {
		case pkgconfig.CompressGzip:
			ec.LogInfo("gzip compression is enabled")
		default:
			log.Fatal(pkgutils.PrefixLogLogger+"["+ec.name+"] elasticsearch - invalid compress mode: ", ec.config.Loggers.ElasticSearchClient.Compression)
		}
	}

	ec.server = ec.config.Loggers.ElasticSearchClient.Server
	ec.index = ec.config.Loggers.ElasticSearchClient.Index

	u, err := url.Parse(ec.server)
	if err != nil {
		ec.LogError(err.Error())
	}
	u.Path = path.Join(u.Path, ec.index, "_bulk")
	ec.bulkURL = u.String()
}

func (ec *ElasticSearchClient) ReloadConfig(config *pkgconfig.Config) {
	ec.LogInfo("reload configuration!")
	ec.configChan <- config
}

func (ec *ElasticSearchClient) GetInputChannel() chan dnsutils.DNSMessage {
	return ec.inputChan
}

func (ec *ElasticSearchClient) LogInfo(msg string, v ...interface{}) {
	ec.logger.Info(pkgutils.PrefixLogLogger+"["+ec.name+"] elasticsearch - "+msg, v...)
}

func (ec *ElasticSearchClient) LogError(msg string, v ...interface{}) {
	ec.logger.Error(pkgutils.PrefixLogLogger+"["+ec.name+"] elasticsearch - "+msg, v...)
}

func (ec *ElasticSearchClient) Stop() {
	ec.LogInfo("stopping logger...")
	ec.RoutingHandler.Stop()

	ec.LogInfo("stopping to run...")
	ec.stopRun <- true
	<-ec.doneRun

	ec.LogInfo("stopping to process...")
	ec.stopProcess <- true
	<-ec.doneProcess
}

func (ec *ElasticSearchClient) StartCollect() {
	ec.LogInfo("worker is starting collection")
	defer func() {
		ec.doneRun <- true
	}()

	// prepare next channels
	defaultRoutes, defaultNames := ec.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := ec.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, ec.outputChan)
	subprocessors := transformers.NewTransforms(&ec.config.OutgoingTransformers, ec.logger, ec.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go ec.ProcessDM()

	// loop to process incoming messages
	for {
		select {
		case <-ec.stopRun:
			// cleanup transformers
			subprocessors.Reset()
			return

		case cfg, opened := <-ec.configChan:
			if !opened {
				return
			}
			ec.config = cfg
			ec.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-ec.inputChan:
			if !opened {
				ec.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				ec.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			ec.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			ec.outputChan <- dm
		}
	}
}

func (ec *ElasticSearchClient) ProcessDM() {
	ec.LogInfo("waiting transformed dnsmessage to process...")
	defer func() {
		ec.LogInfo("processing terminated")
		ec.doneProcess <- true
	}()

	// create a new encoder that writes to the buffer
	buffer := bytes.NewBuffer(make([]byte, 0, ec.config.Loggers.ElasticSearchClient.BulkSize))
	encoder := json.NewEncoder(buffer)

	flushInterval := time.Duration(ec.config.Loggers.ElasticSearchClient.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	dataBuffer := make(chan []byte, ec.config.Loggers.ElasticSearchClient.BulkChannelSize)
	go func() {
		for data := range dataBuffer {
			var err error
			if ec.config.Loggers.ElasticSearchClient.Compression == pkgconfig.CompressGzip {
				err = ec.sendCompressedBulk(data)
			} else {
				err = ec.sendBulk(data)
			}
			if err != nil {
				ec.LogError("error sending bulk data: %v", err)
			}
		}
	}()

	for {
		select {
		case <-ec.stopProcess:
			close(dataBuffer)
			return

		// incoming dns message to process
		case dm, opened := <-ec.outputChan:
			if !opened {
				ec.LogInfo("output channel closed!")
				return
			}

			// append dns message to buffer
			flat, err := dm.Flatten()
			if err != nil {
				ec.LogError("flattening DNS message failed: %e", err)
			}
			buffer.WriteString("{ \"create\" : {}}\n")
			encoder.Encode(flat)

			// Send data and reset buffer
			if buffer.Len() >= ec.config.Loggers.ElasticSearchClient.BulkSize {
				bufCopy := make([]byte, buffer.Len())
				buffer.Read(bufCopy)
				buffer.Reset()

				select {
				case dataBuffer <- bufCopy:
				default:
					ec.LogError("Send buffer is full, bulk dropped")
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
					ec.LogError("automatic flush, send buffer is full, bulk dropped")
				}
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
}

func (ec *ElasticSearchClient) sendBulk(bulk []byte) error {
	// Create a new HTTP request
	req, err := http.NewRequest("POST", ec.bulkURL, bytes.NewReader(bulk))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request using the HTTP client
	resp, err := ec.httpClient.Do(req)
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

func (ec *ElasticSearchClient) sendCompressedBulk(bulk []byte) error {
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
	req, err := http.NewRequest("POST", ec.bulkURL, &compressedBulk)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip") // Set Content-Encoding header to gzip

	// Send the request using the HTTP client
	resp, err := ec.httpClient.Do(req)
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
