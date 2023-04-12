package loggers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/gogo/protobuf/proto"
	"github.com/grafana/dskit/backoff"
	"github.com/klauspost/compress/snappy"

	/*
		install loki with tags
		go get github.com/grafana/loki@90888a0cc737b60f29b8bed880a380731ae1e492
		https://github.com/grafana/loki/releases/tag/v2.8.0

		go get github.com/deepmap/oapi-codegen@v1.12.4
		go get github.com/prometheus/prometheus@v0.42.0
		go mod tidy
	*/
	"github.com/grafana/loki/pkg/logproto"
)

type LokiStream struct {
	name        string
	config      *dnsutils.Config
	logger      *logger.Logger
	stream      *logproto.Stream
	pushrequest *logproto.PushRequest
	sizeentries int
}

func (o *LokiStream) Init() {
	// prepare stream with label name
	o.stream = &logproto.Stream{}
	o.stream.Labels = "{job=\"" + o.config.Loggers.LokiClient.JobName + "\", identity=\"" + o.name + "\"}"

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
	done       chan bool
	channel    chan dnsutils.DnsMessage
	config     *dnsutils.Config
	logger     *logger.Logger
	exit       chan bool
	httpclient *http.Client
	textFormat []string
	streams    map[string]*LokiStream
	name       string
}

func NewLokiClient(config *dnsutils.Config, logger *logger.Logger, name string) *LokiClient {
	logger.Info("[%s] logger loki - enabled", name)

	s := &LokiClient{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
		streams: make(map[string]*LokiStream),
		name:    name,
	}

	s.ReadConfig()

	return s
}

func (c *LokiClient) GetName() string { return c.name }

func (c *LokiClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *LokiClient) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.LokiClient.TlsMinVersion) {
		o.logger.Fatal("logger loki - invalid tls min version")
	}

	if len(o.config.Loggers.LokiClient.TextFormat) > 0 {
		o.textFormat = strings.Fields(o.config.Loggers.LokiClient.TextFormat)
	} else {
		o.textFormat = strings.Fields(o.config.Global.TextFormat)
	}

	// tls client config
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
	tlsConfig.InsecureSkipVerify = o.config.Loggers.LokiClient.TlsInsecure
	tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.LokiClient.TlsMinVersion]

	// prepare http client
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		TLSClientConfig:    tlsConfig,
	}

	// use proxy
	if len(o.config.Loggers.LokiClient.ProxyURL) > 0 {
		proxyURL, err := url.Parse(o.config.Loggers.LokiClient.ProxyURL)
		if err != nil {
			o.logger.Fatal("unable to parse proxy url: ", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	o.httpclient = &http.Client{Transport: tr}
}

func (o *LokiClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger loki - "+msg, v...)
}

func (o *LokiClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger loki - "+msg, v...)
}

func (o *LokiClient) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *LokiClient) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *LokiClient) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.channel)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel)

	// prepare buffer
	buffer := new(bytes.Buffer)

	// prepare timers
	tflush_interval := time.Duration(o.config.Loggers.LokiClient.FlushInterval) * time.Second
	tflush := time.NewTimer(tflush_interval)

LOOP:
	for {
		select {
		case dm := <-o.channel:
			// apply tranforms
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			if _, ok := o.streams[dm.DnsTap.Identity]; !ok {
				o.streams[dm.DnsTap.Identity] = &LokiStream{config: o.config, logger: o.logger, name: dm.DnsTap.Identity}
				o.streams[dm.DnsTap.Identity].Init()
			}

			// prepare entry
			entry := logproto.Entry{}
			entry.Timestamp = time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))

			switch o.config.Loggers.LokiClient.Mode {
			case dnsutils.MODE_TEXT:
				entry.Line = string(dm.Bytes(o.textFormat,
					o.config.Global.TextFormatDelimiter,
					o.config.Global.TextFormatBoundary))
			case dnsutils.MODE_JSON:
				json.NewEncoder(buffer).Encode(dm)
				entry.Line = buffer.String()
				buffer.Reset()
			case dnsutils.MODE_FLATJSON:
				flat, err := dm.Flatten()
				if err != nil {
					o.LogError("flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				entry.Line = buffer.String()
				buffer.Reset()
			}
			o.streams[dm.DnsTap.Identity].sizeentries += len(entry.Line)

			// append entry to the stream
			o.streams[dm.DnsTap.Identity].stream.Entries = append(o.streams[dm.DnsTap.Identity].stream.Entries, entry)

			// flush ?
			if o.streams[dm.DnsTap.Identity].sizeentries >= o.config.Loggers.LokiClient.BatchSize {
				// encode log entries
				buf, err := o.streams[dm.DnsTap.Identity].Encode2Proto()
				if err != nil {
					o.LogError("error encoding log entries - %v", err)
					// reset push request and entries
					o.streams[dm.DnsTap.Identity].ResetEntries()
					return
				}

				// send all entries
				o.SendEntries(buf)

				// reset entries and push request
				o.streams[dm.DnsTap.Identity].ResetEntries()
			}

		case <-tflush.C:
			for _, s := range o.streams {
				if len(s.stream.Entries) > 0 {
					// timeout
					// encode log entries
					buf, err := s.Encode2Proto()
					if err != nil {
						o.LogError("error encoding log entries - %v", err)
						// reset push request and entries
						s.ResetEntries()
						// restart timer
						tflush.Reset(tflush_interval)
						return
					}

					// send all entries
					o.SendEntries(buf)

					// reset entries and push request
					s.ResetEntries()
				}
			}

			// restart timer
			tflush.Reset(tflush_interval)
		case <-o.exit:
			o.logger.Info("closing loop...")
			break LOOP
		}

	}

	// if buffer is not empty, we accept to lose log entries
	o.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	o.done <- true
}

func (o *LokiClient) SendEntries(buf []byte) {

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
		post, err := http.NewRequest("POST", o.config.Loggers.LokiClient.ServerURL, bytes.NewReader(buf))
		if err != nil {
			o.LogError("new http error: %s", err)
			return
		}
		post = post.WithContext(ctx)
		post.Header.Set("Content-Type", "application/x-protobuf")
		post.Header.Set("User-Agent", "dnscollector")
		if len(o.config.Loggers.LokiClient.TenantId) > 0 {
			post.Header.Set("X-Scope-OrgID", o.config.Loggers.LokiClient.TenantId)
		}

		post.SetBasicAuth(
			o.config.Loggers.LokiClient.BasicAuthLogin,
			o.config.Loggers.LokiClient.BasicAuthPwd,
		)

		// send post and read response
		resp, err := o.httpclient.Do(post)
		if err != nil {
			o.LogError("do http error: %s", err)
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
			o.LogError("server returned HTTP status %s (%d): %s", resp.Status, resp.StatusCode, line)
		}

		// wait before retry
		backoff.Wait()

		// Make sure it sends at least once before checking for retry.
		if !backoff.Ongoing() {
			break
		}
	}
}
