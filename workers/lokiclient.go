package workers

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

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/gogo/protobuf/proto"
	"github.com/grafana/dskit/backoff"
	"github.com/klauspost/compress/snappy"

	// go get github.com/grafana/loki/v3/pkg/logproto
	"github.com/grafana/loki/v3/pkg/logproto"
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

func (w *LokiStream) Init() {
	// prepare stream with label name
	w.stream = &logproto.Stream{}
	w.stream.Labels = w.labels.String()

	// creates push request
	w.pushrequest = &logproto.PushRequest{
		Streams: make([]logproto.Stream, 0, 1),
	}
}

func (w *LokiStream) ResetEntries() {
	w.stream.Entries = nil
	w.sizeentries = 0
	w.pushrequest.Reset()
}

func (w *LokiStream) Encode2Proto() ([]byte, error) {
	w.pushrequest.Streams = append(w.pushrequest.Streams, *w.stream)

	buf, err := proto.Marshal(w.pushrequest)
	if err != nil {
		fmt.Println(err)
	}
	buf = snappy.Encode(nil, buf)
	return buf, nil
}

type LokiClient struct {
	*GenericWorker
	httpclient *http.Client
	textFormat []string
	streams    map[string]*LokiStream
}

func NewLokiClient(config *pkgconfig.Config, logger *logger.Logger, name string) *LokiClient {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Loggers.LokiClient.ChannelBufferSize > 0 {
		bufSize = config.Loggers.LokiClient.ChannelBufferSize
	}
	w := &LokiClient{GenericWorker: NewGenericWorker(config, logger, name, "loki", bufSize, pkgconfig.DefaultMonitor)}
	w.streams = make(map[string]*LokiStream)
	w.ReadConfig()
	return w
}

func (w *LokiClient) ReadConfig() {
	if len(w.GetConfig().Loggers.LokiClient.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.LokiClient.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	// tls client config
	tlsOptions := netutils.TLSOptions{
		InsecureSkipVerify: w.GetConfig().Loggers.LokiClient.TLSInsecure,
		MinVersion:         w.GetConfig().Loggers.LokiClient.TLSMinVersion,
		CAFile:             w.GetConfig().Loggers.LokiClient.CAFile,
		CertFile:           w.GetConfig().Loggers.LokiClient.CertFile,
		KeyFile:            w.GetConfig().Loggers.LokiClient.KeyFile,
	}

	tlsConfig, err := netutils.TLSClientConfig(tlsOptions)
	if err != nil {
		w.LogFatal(pkgconfig.PrefixLogWorker+"["+w.GetName()+"] loki - tls config failed:", err)
	}

	// prepare http client
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		TLSClientConfig:    tlsConfig,
	}

	// use proxy
	if len(w.GetConfig().Loggers.LokiClient.ProxyURL) > 0 {
		proxyURL, err := url.Parse(w.GetConfig().Loggers.LokiClient.ProxyURL)
		if err != nil {
			w.LogFatal("logger=loki - unable to parse proxy url: ", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	w.httpclient = &http.Client{Transport: tr}

	if w.GetConfig().Loggers.LokiClient.BasicAuthPwdFile != "" {
		content, err := os.ReadFile(w.GetConfig().Loggers.LokiClient.BasicAuthPwdFile)
		if err != nil {
			w.LogFatal("logger=loki - unable to load password from file: ", err)
		}
		w.GetConfig().Loggers.LokiClient.BasicAuthPwd = string(content)
	}
}

func (w *LokiClient) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

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
			// count global messages
			w.CountIngressTraffic()

			// apply tranforms, init dns message with additionnals parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.CountEgressTraffic()
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *LokiClient) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// prepare buffer
	buffer := new(bytes.Buffer)
	var byteBuffer []byte

	// prepare timers
	tflushInterval := time.Duration(w.GetConfig().Loggers.LokiClient.FlushInterval) * time.Second
	tflush := time.NewTimer(tflushInterval)

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

			lbls := labels.Labels{
				labels.Label{Name: "identity", Value: dm.DNSTap.Identity},
				labels.Label{Name: "job", Value: w.GetConfig().Loggers.LokiClient.JobName},
			}
			var err error
			var flat map[string]interface{}
			if len(w.GetConfig().Loggers.LokiClient.RelabelConfigs) > 0 {
				// Save flattened JSON in case it's used when populating the message of the log entry.
				// There is more room for improvement for reusing data though. Flatten() internally
				// does a JSON encode of the DnsMessage, but it's not saved to use when the mode
				// is JSON.
				flat, err = dm.Flatten()
				if err != nil {
					w.LogError("flattening DNS message failed: %e", err)
				}
				sb := labels.NewScratchBuilder(len(lbls) + len(flat))
				sb.Assign(lbls)
				for k, v := range flat {
					sb.Add(fmt.Sprintf("__%s", strings.ReplaceAll(k, ".", "_")), fmt.Sprint(v))
				}
				sb.Sort()
				lbls, _ = relabel.Process(sb.Labels(), w.GetConfig().Loggers.LokiClient.RelabelConfigs...)

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
					w.LogInfo("dropping %v since it has no labels", dm)
					continue
				}
			}

			// prepare entry
			entry := logproto.Entry{}
			entry.Timestamp = time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))

			switch w.GetConfig().Loggers.LokiClient.Mode {
			case pkgconfig.ModeText:
				entry.Line = string(dm.Bytes(w.textFormat,
					w.GetConfig().Global.TextFormatDelimiter,
					w.GetConfig().Global.TextFormatBoundary))
			case pkgconfig.ModeJSON:
				json.NewEncoder(buffer).Encode(dm)
				entry.Line = buffer.String()
				buffer.Reset()
			case pkgconfig.ModeFlatJSON:
				if len(flat) == 0 {
					flat, err = dm.Flatten()
					if err != nil {
						w.LogError("flattening DNS message failed: %e", err)
					}
				}
				json.NewEncoder(buffer).Encode(flat)
				entry.Line = buffer.String()
				buffer.Reset()
			}
			key := string(lbls.Bytes(byteBuffer))
			ls, ok := w.streams[key]
			if !ok {
				ls = &LokiStream{config: w.GetConfig(), logger: w.GetLogger(), labels: lbls}
				ls.Init()
				w.streams[key] = ls
			}
			ls.sizeentries += len(entry.Line)

			// append entry to the stream
			ls.stream.Entries = append(ls.stream.Entries, entry)

			// flush ?
			if ls.sizeentries >= w.GetConfig().Loggers.LokiClient.BatchSize {
				// encode log entries
				buf, err := ls.Encode2Proto()
				if err != nil {
					w.LogError("error encoding log entries - %v", err)
					// reset push request and entries
					ls.ResetEntries()
					return
				}

				// send all entries
				w.SendEntries(buf)

				// reset entries and push request
				ls.ResetEntries()
			}

		case <-tflush.C:
			for _, s := range w.streams {
				if len(s.stream.Entries) > 0 {
					// timeout
					// encode log entries
					buf, err := s.Encode2Proto()
					if err != nil {
						w.LogError("error encoding log entries - %v", err)
						// reset push request and entries
						s.ResetEntries()
						// restart timer
						tflush.Reset(tflushInterval)
						return
					}

					// send all entries
					w.SendEntries(buf)

					// reset entries and push request
					s.ResetEntries()
				}
			}

			// restart timer
			tflush.Reset(tflushInterval)
		}
	}
}

func (w *LokiClient) SendEntries(buf []byte) {

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
		post, err := http.NewRequest("POST", w.GetConfig().Loggers.LokiClient.ServerURL, bytes.NewReader(buf))
		if err != nil {
			w.LogError("new http error: %s", err)
			return
		}
		post = post.WithContext(ctx)
		post.Header.Set("Content-Type", "application/x-protobuf")
		post.Header.Set("User-Agent", w.GetConfig().GetServerIdentity())
		if len(w.GetConfig().Loggers.LokiClient.TenantID) > 0 {
			post.Header.Set("X-Scope-OrgID", w.GetConfig().Loggers.LokiClient.TenantID)
		}

		post.SetBasicAuth(
			w.GetConfig().Loggers.LokiClient.BasicAuthLogin,
			w.GetConfig().Loggers.LokiClient.BasicAuthPwd,
		)

		// send post and read response
		resp, err := w.httpclient.Do(post)
		if err != nil {
			w.LogError("do http error: %s", err)
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
			w.LogError("server returned HTTP status %s (%d): %s", resp.Status, resp.StatusCode, line)
		}

		// wait before retry
		backoff.Wait()

		// Make sure it sends at least once before checking for retry.
		if !backoff.Ongoing() {
			break
		}
	}
}
