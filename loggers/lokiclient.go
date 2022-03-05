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
	"github.com/dmachard/go-logger"
	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/compress/snappy"

	/*
		workaround to install latest version of loki with tags
		go get github.com/grafana/loki@f61a4d2612d8fa3a385c90c363301ec05bab34d8 github.com/deepmap/oapi-codegen@v1.9.1
	*/
	"github.com/grafana/loki/pkg/logproto"
)

type LokiClient struct {
	done        chan bool
	channel     chan dnsutils.DnsMessage
	config      *dnsutils.Config
	logger      *logger.Logger
	exit        chan bool
	stream      *logproto.Stream
	pushrequest *logproto.PushRequest
	httpclient  *http.Client
	textFormat  []string
	sizeentries int
}

func NewLokiClient(config *dnsutils.Config, logger *logger.Logger) *LokiClient {
	logger.Info("logger loki - enabled")

	s := &LokiClient{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
	}

	s.ReadConfig()

	return s
}

func (o *LokiClient) ReadConfig() {
	if len(o.config.Loggers.LokiClient.TextFormat) > 0 {
		o.textFormat = strings.Fields(o.config.Loggers.LokiClient.TextFormat)
	} else {
		o.textFormat = strings.Fields(o.config.Subprocessors.TextFormat)
	}

	// tls client config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: o.config.Loggers.LokiClient.TlsInsecure,
	}

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
	o.logger.Info("logger loki - "+msg, v...)
}

func (o *LokiClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("logger loki - "+msg, v...)
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
	buffer := new(bytes.Buffer)

	// prepare stream with label name

	o.stream = &logproto.Stream{}
	o.stream.Labels = "{job=\"" + o.config.Loggers.LokiClient.JobName + "\"}"

	// creates push request
	o.pushrequest = &logproto.PushRequest{
		Streams: make([]logproto.Stream, 0, 1),
	}

	tflush_interval := time.Duration(o.config.Loggers.LokiClient.FlushInterval) * time.Second
	tflush := time.NewTimer(tflush_interval)

LOOP:
	for {
	LOOP_RECONNECT:
		for {
			select {
			case dm := <-o.channel:
				// prepare entry
				entry := logproto.Entry{}
				entry.Timestamp = time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec))

				switch o.config.Loggers.LokiClient.Mode {
				case "text":
					delimiter := ""
					entry.Line = string(dm.Bytes(o.textFormat, delimiter))
				case "json":
					json.NewEncoder(buffer).Encode(dm)
					entry.Line = buffer.String()
					buffer.Reset()
				}
				o.sizeentries += len(entry.Line)

				// append entry to the stream
				o.stream.Entries = append(o.stream.Entries, entry)

				if o.sizeentries >= o.config.Loggers.LokiClient.BatchSize {
					// encode log entries
					buf, err := o.ProtoEncode()
					if err != nil {
						o.LogError("error encoding log entries - %v", err)
						// reset push request and entries
						o.ResetEntries()
						return
					}

					// send all entries
					err = o.SendEntries(buf)
					if err != nil {
						o.LogError("error sending log entries - %v", err)
						break LOOP_RECONNECT
					}

					// reset entries and push request
					o.ResetEntries()
				}

			case <-tflush.C:
				if len(o.stream.Entries) > 0 {
					// timeout
					// encode log entries
					buf, err := o.ProtoEncode()
					if err != nil {
						o.LogError("error encoding log entries - %v", err)
						// reset push request and entries
						o.ResetEntries()
						// restart timer
						tflush.Reset(tflush_interval)
						return
					}

					// send all entries
					err = o.SendEntries(buf)
					if err != nil {
						o.LogError("error sending log entries - %v", err)
						// restart timer
						tflush.Reset(tflush_interval)

						break LOOP_RECONNECT
					}

					// reset entries and push request
					o.ResetEntries()
				}
				// restart timer
				tflush.Reset(tflush_interval)

			case <-o.exit:
				o.logger.Info("closing loop...")
				break LOOP
			}

		}
		o.LogInfo("retry in %d seconds", o.config.Loggers.LokiClient.RetryInterval)
		time.Sleep(time.Duration(o.config.Loggers.LokiClient.RetryInterval) * time.Second)
	}

	// if buffer is not empty, we accept to lose log entries
	o.LogInfo("run terminated")
	// the job is done
	o.done <- true
}

func (o *LokiClient) ProtoEncode() ([]byte, error) {
	o.pushrequest.Streams = append(o.pushrequest.Streams, *o.stream)

	buf, err := proto.Marshal(o.pushrequest)
	if err != nil {
		fmt.Println(err)
	}
	buf = snappy.Encode(nil, buf)
	return buf, nil
}

func (o *LokiClient) ResetEntries() {
	o.stream.Entries = nil
	o.sizeentries = 0
	o.pushrequest.Reset()
}

func (o *LokiClient) SendEntries(buf []byte) error {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// send post http
	post, err := http.NewRequest("POST", o.config.Loggers.LokiClient.ServerURL, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	post = post.WithContext(ctx)
	post.Header.Set("Content-Type", "application/x-protobuf")
	post.Header.Set("User-Agent", "dnscollector")
	if len(o.config.Loggers.LokiClient.TenantId) > 0 {
		post.Header.Set("X-Scope-OrgID", o.config.Loggers.LokiClient.TenantId)
	}

	post.SetBasicAuth(o.config.Loggers.LokiClient.BasicAuthLogin, o.config.Loggers.LokiClient.BasicAuthPwd)

	// send post and read response
	resp, err := o.httpclient.Do(post)
	if err != nil {
		return err
	}

	if resp.StatusCode/100 != 2 {
		scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1024))
		line := ""
		if scanner.Scan() {
			line = scanner.Text()
		}
		return fmt.Errorf("server returned HTTP status %s (%d): %s", resp.Status, resp.StatusCode, line)
	}

	return nil
}
