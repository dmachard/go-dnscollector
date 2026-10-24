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

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/gogo/protobuf/proto"
	"github.com/grafana/dskit/backoff"
	"github.com/klauspost/compress/snappy"

	// go get github.com/grafana/loki/v3/pkg/logproto
	"github.com/grafana/loki/v3/pkg/logproto"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
)

type LokiStream struct {
	labels      labels.Labels
	config      *config.Config
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
	httpclient    *http.Client
	textFormat    []string
	textFormatter *dnsutils.TextFormatter
	streams       map[string]*LokiStream

	// Relabelling reads a handful of message fields, but a flattened message has
	// about a hundred. relabelWanted holds the internal label names the rules
	// read (their source labels); only those are built per message, unless a
	// rule needs every label (labelmap), then relabelAll is set.
	relabelAll    bool
	relabelWanted map[string]struct{}
	// flattened key -> internal label name ("dns.qname" -> "__dns_qname")
	relabelNames map[string]string
}

// relabelNamesMax bounds the flattened-key cache: keys that carry an index
// (one per resource record) are not cached past it.
const relabelNamesMax = 4096

func relabelLabelName(key string) string {
	return "__" + strings.ReplaceAll(strings.ReplaceAll(key, ".", "_"), "-", "_")
}

func NewLokiClient(cfg *config.Config, logger *logger.Logger, name string) *LokiClient {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &LokiClient{GenericWorker: NewGenericWorker(cfg, logger, name, "loki", bufSize, config.DefaultMonitor)}
	w.streams = make(map[string]*LokiStream)
	w.ReadConfig()
	return w
}

func (w *LokiClient) ReadConfig() {
	w.readRelabelConfig()
	if len(w.GetConfig().Loggers.LokiClient.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.LokiClient.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	var errFormatter error
	w.textFormatter, errFormatter = dnsutils.NewTextFormatter(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
	if errFormatter != nil {
		w.LogFatal(config.PrefixLogWorker + "[" + w.GetName() + "] loki - invalid text format: " + errFormatter.Error())
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
		w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] loki - tls config failed:", err)
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

// readRelabelConfig works out which labels the relabel rules read, and sets
// the rules' name validation scheme once instead of on every message.
func (w *LokiClient) readRelabelConfig() {
	w.relabelAll = false
	w.relabelWanted = make(map[string]struct{})
	w.relabelNames = make(map[string]string)
	for _, rc := range w.GetConfig().Loggers.LokiClient.RelabelConfigs {
		// to support prometheus > 3.0.7
		if rc.NameValidationScheme == model.UnsetValidation {
			rc.NameValidationScheme = model.LegacyValidation
		}
		switch rc.Action {
		case relabel.LabelMap:
			// maps every label whose name matches: needs them all
			w.relabelAll = true
		case relabel.KeepEqual, relabel.DropEqual:
			// compares the source value with the target label's value
			w.relabelWanted[rc.TargetLabel] = struct{}{}
		}
		for _, l := range rc.SourceLabels {
			w.relabelWanted[string(l)] = struct{}{}
		}
	}
}

// relabelInput returns the internal labels the relabel rules can read from dm.
func (w *LokiClient) relabelInput(flat map[string]interface{}, finalSet []labels.Label) []labels.Label {
	for k, v := range flat {
		name, ok := w.relabelNames[k]
		if !ok {
			name = relabelLabelName(k)
			if len(w.relabelNames) < relabelNamesMax {
				w.relabelNames[k] = name
			}
		}
		if !w.relabelAll {
			if _, wanted := w.relabelWanted[name]; !wanted {
				continue
			}
		}
		finalSet = append(finalSet, labels.Label{Name: name, Value: fmt.Sprint(v)})
	}
	return finalSet
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

		case batch, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}
			outBatch := dnsutils.AcquireDNSMessageBatch(len(batch.Messages))
			for _, dm := range batch.Messages {
				// count global messages
				w.CountIngressTraffic()

				// apply transforms, init dns message with additional parts if necessary
				transformResult, err := subprocessors.ProcessMessage(dm)
				if err != nil {
					w.LogError(err.Error())
				}
				if transformResult == transformers.ReturnDrop {
					w.SendDroppedTo(droppedRoutes, droppedNames, dm)
					continue
				}

				dm.Retain(1)
				outBatch.Messages = append(outBatch.Messages, dm)
			}
			w.SendToOutputAndForwardBatch(defaultRoutes, defaultNames, outBatch)
			batch.Release()
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

	chanSize := w.GetConfig().Loggers.LokiClient.BatchChannelSize
	if chanSize <= 0 {
		chanSize = 10
	}
	if w.GetConfig().Global.Worker.ChannelBufferSize > 0 && w.GetConfig().Global.Worker.ChannelBufferSize < chanSize {
		chanSize = w.GetConfig().Global.Worker.ChannelBufferSize
	}

	dataBuffer := make(chan []byte, chanSize)
	senderDone := make(chan struct{})

	go func() {
		defer close(senderDone)
		for data := range dataBuffer {
			w.SendEntries(data)
		}
	}()

	sendBatch := func(buf []byte) {
		select {
		case dataBuffer <- buf:
		default:
			w.CountEgressDiscarded()
			w.LogWarning("send buffer is full, batch dropped")
		}
	}

	for {
		select {
		case <-w.OnLoggerStopped():
			close(dataBuffer)
			<-senderDone
			return

		// incoming dns message to process
		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				close(dataBuffer)
				<-senderDone
				return
			}

			for _, dm := range batch.Messages {
				lbls := labels.FromStrings(
					"identity", dm.DNSTap.Identity,
					"job", w.GetConfig().Loggers.LokiClient.JobName,
				)
				var err error
				var flat map[string]interface{}
				if len(w.GetConfig().Loggers.LokiClient.RelabelConfigs) > 0 {
					finalSet := []labels.Label{
						{Name: "identity", Value: dm.DNSTap.Identity},
						{Name: "job", Value: w.GetConfig().Loggers.LokiClient.JobName},
					}
					// flatten dns message
					flat, err = dm.Flatten()
					if err != nil {
						w.LogError("flattening DNS message failed: %e", err)
						w.CountEgressDiscarded()
						continue
					}
					finalSet = w.relabelInput(flat, finalSet)

					// Apply relabeling
					ls := labels.New(finalSet...)
					sb := labels.NewBuilder(ls)

					keep := relabel.ProcessBuilder(sb, w.GetConfig().Loggers.LokiClient.RelabelConfigs...)
					if !keep {
						w.LogInfo("dropping %v because of relabel config", dm)
						w.CountEgressDiscarded()
						continue
					}

					// remove internal labels
					sb.Range(func(l labels.Label) {
						if strings.HasPrefix(l.Name, "__") {
							sb.Del(l.Name)
						}
					})

					lbls = sb.Labels()
					if lbls.Len() == 0 {
						w.LogInfo("dropping %v since it has no labels", dm)
						w.CountEgressDiscarded()
						continue
					}
				}

				// prepare entry
				entry := logproto.Entry{}
				entry.Timestamp = time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))

				switch w.GetConfig().Loggers.LokiClient.Mode {
				case config.ModeText:
					// get buffer from pool
					buf := w.GetTextBuffer()
					buf.Reset()

					// write the DNSMessage to the buffer
					var err error
					if w.textFormatter != nil {
						err = w.textFormatter.Format(dm, buf)
					} else {
						err = dm.ToTextLine(
							w.textFormat,
							w.GetConfig().Global.TextFormatDelimiter,
							w.GetConfig().Global.TextFormatBoundary,
							buf,
						)
					}
					if err != nil {
						w.CountEgressDiscarded()
						w.LogError("process: could not encode to text format: %s", err)
						w.PutTextBuffer(buf)
						continue
					}

					// assign buffer content to Loki entry
					entry.Line = buf.String()

					// return buffer to pool
					w.PutTextBuffer(buf)

				case config.ModeJSON:
					dm.GetTimestampRFC3339()
					dm.EncodeJSON(buffer)
					buffer.WriteByte('\n')
					entry.Line = buffer.String()
					buffer.Reset()
				case config.ModeFlatJSON:
					switch {
					case len(flat) > 0:
						json.NewEncoder(buffer).Encode(flat)
						entry.Line = buffer.String()
						buffer.Reset()
					case dm.Relabeling != nil:
						flat, err = dm.Flatten()
						if err != nil {
							w.LogError("flattening DNS message failed: %e", err)
							w.CountEgressDiscarded()
							continue
						}
						json.NewEncoder(buffer).Encode(flat)
						entry.Line = buffer.String()
						buffer.Reset()
					default:
						buffer.Reset()
						dm.GetTimestampRFC3339()
						dm.EncodeFlatJSON(buffer)
						buffer.WriteByte('\n')
						entry.Line = buffer.String()
						buffer.Reset()
					}
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
						w.CountEgressDiscarded()
						return
					}

					// send batch to queue
					sendBatch(buf)

					// reset entries and push request
					ls.ResetEntries()
				}
			}
			batch.Release()

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
						w.CountEgressDiscarded()
						return
					}

					// send batch to queue
					sendBatch(buf)

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

	ctx, cancel := context.WithCancel(w.Context())
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
			if ctx.Err() != nil {
				return
			}
			w.LogError("do http error: %s", err)
			return
		}

		// something is wrong, log error response
		if resp.StatusCode/100 != 2 {
			scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1024))
			line := ""
			if scanner.Scan() {
				line = scanner.Text()
			}
			w.LogError("server returned HTTP status %s (%d): %s", resp.Status, resp.StatusCode, line)
		}
		_ = resp.Body.Close()

		// success ?
		if resp.StatusCode > 0 && resp.StatusCode != 429 && resp.StatusCode/100 != 5 {
			break
		}

		// wait before retry
		backoff.Wait()

		// Make sure it sends at least once before checking for retry.
		if !backoff.Ongoing() {
			break
		}
	}
}

func init() {
	RegisterLogger("lokiclient", func(c *config.Config) bool { return c.Loggers.LokiClient.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewLokiClient(c, l, s)
	})
}
