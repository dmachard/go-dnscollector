package loggers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/gogo/protobuf/proto"
	"github.com/grafana/dskit/backoff"
	"github.com/klauspost/compress/snappy"

	/*
		install loki with tags

		go get github.com/grafana/loki@2535f9bedeae5f27abdbfaf0cc1a8e9f91b6c96d
		https://github.com/grafana/loki/releases/tag/v2.9.3

		go get github.com/grafana/loki/pkg/push@2535f9bedeae5f27abdbfaf0cc1a8e9f91b6c96d

		go get github.com/prometheus/prometheus@v0.43.1-0.20230419161410-69155c6ba1e9
		go mod tidy
	*/
	"github.com/grafana/loki/pkg/logproto"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
)

type LokiStream struct {
	labels      labels.Labels
	config      *pkgconfig.Config
	logger      *logger.Logger
	stream      *logproto.Stream
	pushrequest *logproto.PushRequest
	sizeentries int
}

func (o *LokiStream) Init() {
	// prepare stream with label name
	o.stream = &logproto.Stream{}
	o.stream.Labels = o.labels.String()

	// creates push request
	o.pushrequest = &logproto.PushRequest{
		Streams: make([]logproto.Stream, 0, 1),
	}
}

func (o *LokiStream) ResetEntries() {
	o.stream.Entries = nil
	o.sizeentries = 0
	o.pushrequest.Reset()
}

func (o *LokiStream) Encode2Proto() ([]byte, error) {
	o.pushrequest.Streams = append(o.pushrequest.Streams, *o.stream)

	buf, err := proto.Marshal(o.pushrequest)
	if err != nil {
		fmt.Println(err)
	}
	buf = snappy.Encode(nil, buf)
	return buf, nil
}

type LokiClient struct {
	stopProcess    chan bool
	doneProcess    chan bool
	stopRun        chan bool
	doneRun        chan bool
	inputChan      chan dnsutils.DNSMessage
	outputChan     chan dnsutils.DNSMessage
	config         *pkgconfig.Config
	configChan     chan *pkgconfig.Config
	logger         *logger.Logger
	httpclient     *http.Client
	textFormat     []string
	streams        map[string]*LokiStream
	name           string
	RoutingHandler pkgutils.RoutingHandler
}

func NewLokiClient(config *pkgconfig.Config, logger *logger.Logger, name string) *LokiClient {
	logger.Info("[%s] logger=loki - enabled", name)

	s := &LokiClient{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.LokiClient.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.LokiClient.ChannelBufferSize),
		logger:         logger,
		config:         config,
		configChan:     make(chan *pkgconfig.Config),
		streams:        make(map[string]*LokiStream),
		name:           name,
		RoutingHandler: pkgutils.NewRoutingHandler(config, logger, name),
	}

	s.ReadConfig()
	return s
}

func (c *LokiClient) GetName() string { return c.name }

func (c *LokiClient) AddDroppedRoute(wrk pkgutils.Worker) {
	c.RoutingHandler.AddDroppedRoute(wrk)
}

func (c *LokiClient) AddDefaultRoute(wrk pkgutils.Worker) {
	c.RoutingHandler.AddDefaultRoute(wrk)
}

func (c *LokiClient) SetLoggers(loggers []pkgutils.Worker) {}

func (c *LokiClient) ReadConfig() {
	if len(c.config.Loggers.LokiClient.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.LokiClient.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}

	// tls client config
	tlsOptions := pkgconfig.TLSOptions{
		InsecureSkipVerify: c.config.Loggers.LokiClient.TLSInsecure,
		MinVersion:         c.config.Loggers.LokiClient.TLSMinVersion,
		CAFile:             c.config.Loggers.LokiClient.CAFile,
		CertFile:           c.config.Loggers.LokiClient.CertFile,
		KeyFile:            c.config.Loggers.LokiClient.KeyFile,
	}

	tlsConfig, err := pkgconfig.TLSClientConfig(tlsOptions)
	if err != nil {
		c.logger.Fatal("logger=loki - tls config failed:", err)
	}

	// prepare http client
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		TLSClientConfig:    tlsConfig,
	}

	// use proxy
	if len(c.config.Loggers.LokiClient.ProxyURL) > 0 {
		proxyURL, err := url.Parse(c.config.Loggers.LokiClient.ProxyURL)
		if err != nil {
			c.logger.Fatal("logger=loki - unable to parse proxy url: ", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	c.httpclient = &http.Client{Transport: tr}

	if c.config.Loggers.LokiClient.BasicAuthPwdFile != "" {
		content, err := os.ReadFile(c.config.Loggers.LokiClient.BasicAuthPwdFile)
		if err != nil {
			c.logger.Fatal("logger=loki - unable to load password from file: ", err)
		}
		c.config.Loggers.LokiClient.BasicAuthPwd = string(content)
	}
}

func (c *LokiClient) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *LokiClient) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=loki - "+msg, v...)
}

func (c *LokiClient) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=loki - "+msg, v...)
}

func (c *LokiClient) GetInputChannel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *LokiClient) Stop() {
	c.LogInfo("stopping routing handler...")
	c.RoutingHandler.Stop()

	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess
}

func (c *LokiClient) Run() {
	c.LogInfo("running in background...")

	// prepare next channels
	defaultRoutes, defaultNames := c.RoutingHandler.GetDefaultRoutes()
	droppedRoutes, droppedNames := c.RoutingHandler.GetDroppedRoutes()

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, c.outputChan)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go c.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-c.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			c.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-c.configChan:
			if !opened {
				return
			}
			c.config = cfg
			c.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-c.inputChan:
			if !opened {
				c.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				c.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next ?
			c.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)

			// send to output channel
			c.outputChan <- dm
		}
	}
	c.LogInfo("run terminated")
}

func (c *LokiClient) Process() {
	// prepare buffer
	buffer := new(bytes.Buffer)
	var byteBuffer []byte

	// prepare timers
	tflushInterval := time.Duration(c.config.Loggers.LokiClient.FlushInterval) * time.Second
	tflush := time.NewTimer(tflushInterval)

	c.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-c.stopProcess:
			c.doneProcess <- true
			break PROCESS_LOOP

		// incoming dns message to process
		case dm, opened := <-c.outputChan:
			if !opened {
				c.LogInfo("output channel closed!")
				return
			}

			lbls := labels.Labels{
				labels.Label{Name: "identity", Value: dm.DNSTap.Identity},
				labels.Label{Name: "job", Value: c.config.Loggers.LokiClient.JobName},
			}
			var err error
			var flat map[string]interface{}
			if len(c.config.Loggers.LokiClient.RelabelConfigs) > 0 {
				// Save flattened JSON in case it's used when populating the message of the log entry.
				// There is more room for improvement for reusing data though. Flatten() internally
				// does a JSON encode of the DnsMessage, but it's not saved to use when the mode
				// is JSON.
				flat, err = dm.Flatten()
				if err != nil {
					c.LogError("flattening DNS message failed: %e", err)
				}
				sb := labels.NewScratchBuilder(len(lbls) + len(flat))
				sb.Assign(lbls)
				for k, v := range flat {
					sb.Add(fmt.Sprintf("__%s", strings.ReplaceAll(k, ".", "_")), fmt.Sprint(v))
				}
				sb.Sort()
				lbls, _ = relabel.Process(sb.Labels(), c.config.Loggers.LokiClient.RelabelConfigs...)

				// Drop all labels starting with __ from the map if a relabel config is used.
				// These labels are just exposed to relabel for the user and should not be
				// shipped to loki by default.
				lb := labels.NewBuilder(lbls)
				lbls.Range(func(l labels.Label) {
					if l.Name[0:2] == "__" {
						lb.Del(l.Name)
					}
				})
				lbls = lb.Labels()

				if len(lbls) == 0 {
					c.LogInfo("dropping %v since it has no labels", dm)
					continue
				}
			}

			// prepare entry
			entry := logproto.Entry{}
			entry.Timestamp = time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))

			switch c.config.Loggers.LokiClient.Mode {
			case pkgconfig.ModeText:
				entry.Line = string(dm.Bytes(c.textFormat,
					c.config.Global.TextFormatDelimiter,
					c.config.Global.TextFormatBoundary))
			case pkgconfig.ModeJSON:
				json.NewEncoder(buffer).Encode(dm)
				entry.Line = buffer.String()
				buffer.Reset()
			case pkgconfig.ModeFlatJSON:
				if len(flat) == 0 {
					flat, err = dm.Flatten()
					if err != nil {
						c.LogError("flattening DNS message failed: %e", err)
					}
				}
				json.NewEncoder(buffer).Encode(flat)
				entry.Line = buffer.String()
				buffer.Reset()
			}
			key := string(lbls.Bytes(byteBuffer))
			ls, ok := c.streams[key]
			if !ok {
				ls = &LokiStream{config: c.config, logger: c.logger, labels: lbls}
				ls.Init()
				c.streams[key] = ls
			}
			ls.sizeentries += len(entry.Line)

			// append entry to the stream
			ls.stream.Entries = append(ls.stream.Entries, entry)

			// flush ?
			if ls.sizeentries >= c.config.Loggers.LokiClient.BatchSize {
				// encode log entries
				buf, err := ls.Encode2Proto()
				if err != nil {
					c.LogError("error encoding log entries - %v", err)
					// reset push request and entries
					ls.ResetEntries()
					return
				}

				// send all entries
				c.SendEntries(buf)

				// reset entries and push request
				ls.ResetEntries()
			}

		case <-tflush.C:
			for _, s := range c.streams {
				if len(s.stream.Entries) > 0 {
					// timeout
					// encode log entries
					buf, err := s.Encode2Proto()
					if err != nil {
						c.LogError("error encoding log entries - %v", err)
						// reset push request and entries
						s.ResetEntries()
						// restart timer
						tflush.Reset(tflushInterval)
						return
					}

					// send all entries
					c.SendEntries(buf)

					// reset entries and push request
					s.ResetEntries()
				}
			}

			// restart timer
			tflush.Reset(tflushInterval)
		}
	}
	c.LogInfo("processing terminated")
}

func (c *LokiClient) SendEntries(buf []byte) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	MinBackoff := 500 * time.Millisecond
	MaxBackoff := 5 * time.Minute
	MaxRetries := 10

	backoff := backoff.New(ctx, backoff.Config{
		MaxBackoff: MaxBackoff,
		MaxRetries: MaxRetries,
		MinBackoff: MinBackoff,
	})

	for {
		// send post http
		post, err := http.NewRequest("POST", c.config.Loggers.LokiClient.ServerURL, bytes.NewReader(buf))
		if err != nil {
			c.LogError("new http error: %s", err)
			return
		}
		post = post.WithContext(ctx)
		post.Header.Set("Content-Type", "application/x-protobuf")
		post.Header.Set("User-Agent", c.config.GetServerIdentity())
		if len(c.config.Loggers.LokiClient.TenantID) > 0 {
			post.Header.Set("X-Scope-OrgID", c.config.Loggers.LokiClient.TenantID)
		}

		post.SetBasicAuth(
			c.config.Loggers.LokiClient.BasicAuthLogin,
			c.config.Loggers.LokiClient.BasicAuthPwd,
		)

		// send post and read response
		resp, err := c.httpclient.Do(post)
		if err != nil {
			c.LogError("do http error: %s", err)
			return
		}

		// success ?
		if resp.StatusCode > 0 && resp.StatusCode != 429 && resp.StatusCode/100 != 5 {
			break
		}

		// something is wrong, retry ?
		if resp.StatusCode/100 != 2 {
			scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1024))
			line := ""
			if scanner.Scan() {
				line = scanner.Text()
			}
			c.LogError("server returned HTTP status %s (%d): %s", resp.Status, resp.StatusCode, line)
		}

		// wait before retry
		backoff.Wait()

		// Make sure it sends at least once before checking for retry.
		if !backoff.Ongoing() {
			break
		}
	}
}
