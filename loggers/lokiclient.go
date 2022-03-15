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
	"github.com/grafana/dskit/backoff"
	"github.com/klauspost/compress/snappy"

	/*
		workaround to install latest version of loki with tags
		go get github.com/grafana/loki@f61a4d2612d8fa3a385c90c363301ec05bab34d8 github.com/deepmap/oapi-codegen@v1.9.1
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
}

func NewLokiClient(config *dnsutils.Config, logger *logger.Logger) *LokiClient {
	logger.Info("logger loki - enabled")

	s := &LokiClient{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
		streams: make(map[string]*LokiStream),
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

	tflush_interval := time.Duration(o.config.Loggers.LokiClient.FlushInterval) * time.Second
	tflush := time.NewTimer(tflush_interval)

LOOP:
	/*	for {
		LOOP_RECONNECT:*/
	for {
		select {
		case dm := <-o.channel:
			if _, ok := o.streams[dm.DnsTap.Identity]; !ok {
				o.streams[dm.DnsTap.Identity] = &LokiStream{config: o.config, logger: o.logger, name: dm.DnsTap.Identity}
				o.streams[dm.DnsTap.Identity].Init()
			}

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
			o.streams[dm.DnsTap.Identity].sizeentries += len(entry.Line)

			// append entry to the stream
			o.streams[dm.DnsTap.Identity].stream.Entries = append(o.streams[dm.DnsTap.Identity].stream.Entries, entry)

			// flush ?
			//fmt.Println(o.streams[dm.DnsTap.Identity].sizeentries)
			if o.streams[dm.DnsTap.Identity].sizeentries >= o.config.Loggers.LokiClient.BatchSize {
				//	fmt.Println("batch completed!")

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

				/*err = o.SendEntries(buf)
				fmt.Println(err)
				if err != nil {
					o.LogError("error sending log entries - %v", err)
					break LOOP_RECONNECT
				})*/

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
					/*	err = o.SendEntries(buf)
						if err != nil {
							o.LogError("error sending log entries - %v", err)
							// restart timer
							tflush.Reset(tflush_interval)
							break LOOP_RECONNECT
						}*/

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
	/*	o.LogInfo("retry in %d seconds", o.config.Loggers.LokiClient.RetryInterval)
		time.Sleep(time.Duration(o.config.Loggers.LokiClient.RetryInterval) * time.Second)
	}*/

	// if buffer is not empty, we accept to lose log entries
	o.LogInfo("run terminated")
	// the job is done
	o.done <- true
}

func (o *LokiClient) SendEntriesOld(buf []byte) error {
	o.LogInfo("sleep in %d seconds", o.config.Loggers.LokiClient.RetryInterval)
	time.Sleep(time.Duration(o.config.Loggers.LokiClient.RetryInterval) * time.Second)

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

		post.SetBasicAuth(o.config.Loggers.LokiClient.BasicAuthLogin, o.config.Loggers.LokiClient.BasicAuthPwd)

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
