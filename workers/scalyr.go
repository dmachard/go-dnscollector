package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grafana/dskit/backoff"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

// ScalyrClient is a client for Scalyr(https://www.dataset.com/)
// This client is using the addEvents endpoint, described here: https://app.scalyr.com/help/api#addEvents
type ScalyrClient struct {
	*GenericWorker

	mode       string
	textFormat []string

	session string // Session ID, used by scalyr, see API docs

	httpclient *http.Client
	endpoint   string       // Where to send the data
	apikey     string       // API Token to use for authorizing requests
	parser     string       // Parser used by Scalyr
	flush      *time.Ticker // Timer that allows us to flush events periodically

	submissions   chan []byte // Marshalled JSON to send to Scalyr
	submitterDone chan bool   // Will be written to when the HTTP submitter is done
}

func NewScalyrClient(config *pkgconfig.Config, console *logger.Logger, name string) *ScalyrClient {
	w := &ScalyrClient{GenericWorker: NewGenericWorker(config, console, name, "scalyr", config.Loggers.ScalyrClient.ChannelBufferSize, pkgconfig.DefaultMonitor)}
	w.mode = pkgconfig.ModeText
	w.endpoint = makeEndpoint("app.scalyr.com")
	w.flush = time.NewTicker(30 * time.Second)
	w.session = uuid.NewString()
	w.submissions = make(chan []byte, 25)
	w.submitterDone = make(chan bool)
	w.ReadConfig()
	return w
}

func makeEndpoint(host string) string {
	return fmt.Sprintf("https://%s/api/addEvents", host)
}

func (w *ScalyrClient) ReadConfig() {
	if len(w.GetConfig().Loggers.ScalyrClient.APIKey) == 0 {
		w.LogFatal("No API Key configured for Scalyr Client")
	}
	w.apikey = w.GetConfig().Loggers.ScalyrClient.APIKey

	if len(w.GetConfig().Loggers.ScalyrClient.Mode) != 0 {
		w.mode = w.GetConfig().Loggers.ScalyrClient.Mode
	}

	if len(w.GetConfig().Loggers.ScalyrClient.Parser) == 0 && (w.mode == pkgconfig.ModeText || w.mode == pkgconfig.ModeJSON) {
		w.LogFatal(fmt.Sprintf("No Scalyr parser configured for Scalyr Client in %s mode", w.mode))
	}
	w.parser = w.GetConfig().Loggers.ScalyrClient.Parser

	if len(w.GetConfig().Loggers.ScalyrClient.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.ScalyrClient.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	if host := w.GetConfig().Loggers.ScalyrClient.ServerURL; host != "" {
		w.endpoint = makeEndpoint(host)
	}

	if flushInterval := w.GetConfig().Loggers.ScalyrClient.FlushInterval; flushInterval != 0 {
		w.flush = time.NewTicker(time.Duration(flushInterval) * time.Second)
	}

	// tls client config
	tlsOptions := netutils.TLSOptions{
		InsecureSkipVerify: w.GetConfig().Loggers.ScalyrClient.TLSInsecure,
		MinVersion:         w.GetConfig().Loggers.ScalyrClient.TLSMinVersion,
		CAFile:             w.GetConfig().Loggers.ScalyrClient.CAFile,
		CertFile:           w.GetConfig().Loggers.ScalyrClient.CertFile,
		KeyFile:            w.GetConfig().Loggers.ScalyrClient.KeyFile,
	}

	tlsConfig, err := netutils.TLSClientConfig(tlsOptions)
	if err != nil {
		w.LogFatal("unable to parse tls confgi: ", err)
	}

	// prepare http client
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		TLSClientConfig:    tlsConfig,
	}

	// use proxy
	if len(w.GetConfig().Loggers.ScalyrClient.ProxyURL) > 0 {
		proxyURL, err := url.Parse(w.GetConfig().Loggers.ScalyrClient.ProxyURL)
		if err != nil {
			w.LogFatal("unable to parse proxy url: ", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	w.httpclient = &http.Client{Transport: tr}
}

func (w *ScalyrClient) StartCollect() {
	w.LogInfo("worker is starting collection")
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

			// apply tranforms, init dns message with additionnals parts if necessary
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

func (w *ScalyrClient) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	sInfo := w.GetConfig().Loggers.ScalyrClient.SessionInfo
	if sInfo == nil {
		sInfo = make(map[string]string)
	}
	attrs := make(map[string]interface{})
	for k, v := range w.GetConfig().Loggers.ScalyrClient.Attrs {
		attrs[k] = v
	}
	if len(w.parser) != 0 {
		attrs["parser"] = w.parser
	}
	var events []event

	if host, ok := sInfo["serverHost"]; !ok || len(host) == 0 {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown-hostname"
		}
		sInfo["serverHost"] = hostname
	}

	w.runSubmitter()

	for {
		select {
		case <-w.OnLoggerStopped():

			if len(events) > 0 {
				w.submitEventRecord(sInfo, events)
			}
			close(w.submissions)

			// Block until both threads are done
			<-w.submitterDone

			return

			// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			switch w.mode {
			case pkgconfig.ModeText:
				attrs["message"] = string(dm.Bytes(w.textFormat,
					w.GetConfig().Global.TextFormatDelimiter,
					w.GetConfig().Global.TextFormatBoundary))
			case pkgconfig.ModeJSON:
				attrs["message"] = dm
			case pkgconfig.ModeFlatJSON:
				var err error
				if attrs, err = dm.Flatten(); err != nil {
					w.LogError("unable to flatten: %e", err)
					break
				}
				// Add user's attrs without overwriting flattened ones
				for k, v := range w.GetConfig().Loggers.ScalyrClient.Attrs {
					if _, ok := attrs[k]; !ok {
						attrs[k] = v
					}
				}
			}
			events = append(events, event{
				TS:    strconv.FormatInt(time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec)).UnixNano(), 10),
				Sev:   SeverityInfo,
				Attrs: attrs,
			})
			if len(events) >= 400 {
				// Maximum size of a POST is 6MB. 400 events would mean that each dnstap entry
				// can be a little over 15 kB in JSON, which should be plenty.
				w.submitEventRecord(sInfo, events)
				events = []event{}
			}
		case <-w.flush.C:
			if len(events) > 0 {
				w.submitEventRecord(sInfo, events)
				events = []event{}
			}
		}
	}
}

func (w *ScalyrClient) submitEventRecord(sessionInfo map[string]string, events []event) {
	er := eventRecord{
		Session:     w.session,
		SessionInfo: sessionInfo,
		Events:      events,
	}
	buf, err := json.Marshal(er)
	if err != nil {
		// TODO should this panic?
		w.LogError("Unable to create JSON from events: %e", err)
	}
	w.submissions <- buf
}

func (w *ScalyrClient) runSubmitter() {
	go func() {
		for m := range w.submissions {
			w.send(m)
		}
		w.submitterDone <- true
	}()
	w.LogInfo("HTTP Submitter started")
}

func (w *ScalyrClient) send(buf []byte) {
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
		post, err := http.NewRequest("POST", w.endpoint, bytes.NewReader(buf))
		if err != nil {
			w.LogError("new http error: %s", err)
			return
		}
		post = post.WithContext(ctx)
		post.Header.Set("Content-Type", "application/json")
		post.Header.Set("User-Agent", "dnscollector")
		post.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.apikey))

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
			response, err := parseServerResponse(resp.Body)
			if err != nil {
				w.LogError("server returned HTTP status %s (%d), unable to decode response: %e", resp.Status, resp.StatusCode, err)
			} else {
				w.LogError("server returned HTTP status %s (%d), %s", resp.Status, resp.StatusCode, response.Message)
			}
		}

		// wait before retry
		backoff.Wait()

		// Make sure it sends at least once before checking for retry.
		if !backoff.Ongoing() {
			break
		}
	}
}

func parseServerResponse(body io.ReadCloser) (response, error) {
	var response response
	b, err := io.ReadAll(body)
	if err != nil {
		return response, err
	}
	err = json.Unmarshal(b, &response)
	return response, err
}

// Models
type scalyrSeverity uint

const (
	SeverityFinest scalyrSeverity = iota
	SeverityFiner
	SeverityFine
	SeverityInfo
	SeverityWarning
	SeverityError
	SeverityFatal
)

type event struct {
	Thread string                 `json:"thread,omitempty"`
	TS     string                 `json:"ts"`
	Sev    scalyrSeverity         `json:"sev,omitempty"`
	Attrs  map[string]interface{} `json:"attrs"`
}

type thread struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type eventRecord struct {
	Token       string            `json:"token,omitempty"`
	Session     string            `json:"session"`
	SessionInfo map[string]string `json:"sessionInfo"`
	Events      []event           `json:"events"`
	Threads     []thread          `json:"threads,omitempty"`
}

type response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}
