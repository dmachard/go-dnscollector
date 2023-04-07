package loggers

import (
	"bytes"
	"context"
	"crypto/tls"
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

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

// ScalyrClient is a client for Scalyr(https://www.dataset.com/)
// This client is using the addEvents endpoint, described here: https://app.scalyr.com/help/api#addEvents
type ScalyrClient struct {
	channel    chan dnsutils.DnsMessage
	logger     *logger.Logger
	name       string
	config     *dnsutils.Config
	mode       string
	textFormat []string

	session string // Session ID, used by scalyr, see API docs

	httpclient *http.Client
	endpoint   string       // Where to send the data
	apikey     string       // API Token to use for authorizing requests
	parser     string       // Parser used by Scalyr
	flush      *time.Ticker // Timer that allows us to flush events periodically

	submissions chan []byte // Marshalled JSON to send to Scalyr

	done          chan bool // Will be written to in Stop()
	runnerDone    chan bool // Will be written to by the main-loop after stopping
	submitterDone chan bool // Will be written to when the HTTP submitter is done
}

func NewScalyrClient(config *dnsutils.Config, console *logger.Logger, name string) *ScalyrClient {
	console.Info("[%s] logger Scalyr - starting", name)
	c := &ScalyrClient{
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  console,
		name:    name,
		config:  config,
		mode:    dnsutils.MODE_TEXT,

		endpoint: makeEndpoint("app.scalyr.com"),
		flush:    time.NewTicker(30 * time.Second),

		session: uuid.NewString(),

		submissions: make(chan []byte, 25),

		done:          make(chan bool),
		runnerDone:    make(chan bool),
		submitterDone: make(chan bool),
	}
	c.ReadConfig()
	return c
}

func makeEndpoint(host string) string {
	return fmt.Sprintf("https://%s/api/addEvents", host)
}

func (c *ScalyrClient) ReadConfig() {
	if len(c.config.Loggers.ScalyrClient.ApiKey) == 0 {
		c.logger.Fatal("No API Key configured for Scalyr Client")
	}
	c.apikey = c.config.Loggers.ScalyrClient.ApiKey

	if len(c.config.Loggers.ScalyrClient.Mode) != 0 {
		c.mode = c.config.Loggers.ScalyrClient.Mode
	}

	if len(c.config.Loggers.ScalyrClient.Parser) == 0 && (c.mode == dnsutils.MODE_TEXT || c.mode == dnsutils.MODE_JSON) {
		c.logger.Fatal(fmt.Sprintf("No Scalyr parser configured for Scalyr Client in %s mode", c.mode))
	}
	c.parser = c.config.Loggers.ScalyrClient.Parser

	if len(c.config.Loggers.ScalyrClient.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.ScalyrClient.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}

	if host := c.config.Loggers.ScalyrClient.ServerURL; host != "" {
		c.endpoint = makeEndpoint(host)
	}

	if flushInterval := c.config.Loggers.ScalyrClient.FlushInterval; flushInterval != 0 {
		c.flush = time.NewTicker(time.Duration(flushInterval) * time.Second)
	}

	tlsMinVersion := "TLS_v12"
	if dnsutils.IsValidTLS(tlsMinVersion) {
		tlsMinVersion = c.config.Loggers.ScalyrClient.TlsMinVersion
	}

	// tls client config
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
	tlsConfig.InsecureSkipVerify = c.config.Loggers.ScalyrClient.TlsInsecure
	tlsConfig.MinVersion = dnsutils.TLS_VERSION[tlsMinVersion]

	// prepare http client
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		TLSClientConfig:    tlsConfig,
	}

	// use proxy
	if len(c.config.Loggers.ScalyrClient.ProxyURL) > 0 {
		proxyURL, err := url.Parse(c.config.Loggers.ScalyrClient.ProxyURL)
		if err != nil {
			c.logger.Fatal("unable to parse proxy url: ", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	c.httpclient = &http.Client{Transport: tr}
}

func (c *ScalyrClient) Run() {
	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, c.channel)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel)

	sInfo := c.config.Loggers.ScalyrClient.SessionInfo
	if sInfo == nil {
		sInfo = make(map[string]string)
	}
	attrs := make(map[string]interface{})
	for k, v := range c.config.Loggers.ScalyrClient.Attrs {
		attrs[k] = v
	}
	if len(c.parser) != 0 {
		attrs["parser"] = c.parser
	}
	var events []event

	if host, ok := sInfo["serverHost"]; !ok || len(host) == 0 {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown-hostname"
		}
		sInfo["serverHost"] = hostname
	}

	c.runSubmitter()

LOOP:
	for {
		select {
		case dm := <-c.channel:
			// apply tranforms
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}
			switch c.mode {
			case dnsutils.MODE_TEXT:
				attrs["message"] = string(dm.Bytes(c.textFormat,
					c.config.Global.TextFormatDelimiter,
					c.config.Global.TextFormatBoundary))
			case dnsutils.MODE_JSON:
				attrs["message"] = dm
			case dnsutils.MODE_FLATJSON:
				var err error
				if attrs, err = dm.Flatten(); err != nil {
					c.LogError("unable to flatten: %e", err)
					break
				}
				// Add user's attrs without overwriting flattened ones
				for k, v := range c.config.Loggers.ScalyrClient.Attrs {
					if _, ok := attrs[k]; !ok {
						attrs[k] = v
					}
				}
			}
			events = append(events, event{
				TS:    strconv.FormatInt(time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec)).UnixNano(), 10),
				Sev:   SeverityInfo,
				Attrs: attrs,
			})
			if len(events) >= 400 {
				// Maximum size of a POST is 6MB. 400 events would mean that each dnstap entry
				// can be a little over 15 kB in JSON, which should be plenty.
				c.submitEventRecord(sInfo, events)
				events = []event{}
			}
		case <-c.flush.C:
			if len(events) > 0 {
				c.submitEventRecord(sInfo, events)
				events = []event{}
			}
		case <-c.done:
			if len(events) > 0 {
				c.submitEventRecord(sInfo, events)
			}
			close(c.submissions)
			break LOOP
		}
	}
	subprocessors.Reset()
	c.runnerDone <- true
}

func (c ScalyrClient) Stop() {
	c.LogInfo("stopping...")

	c.done <- true

	// Block until both threads are done
	<-c.runnerDone
	<-c.submitterDone
}

func (c *ScalyrClient) submitEventRecord(sessionInfo map[string]string, events []event) {
	er := eventRecord{
		Session:     c.session,
		SessionInfo: sessionInfo,
		Events:      events,
	}
	buf, err := json.Marshal(er)
	if err != nil {
		// TODO should this panic?
		c.LogError("Unable to create JSON from events: %e", err)
	}
	c.submissions <- buf
}

func (c *ScalyrClient) runSubmitter() {
	go func() {
		for m := range c.submissions {
			c.send(m)
		}
		c.submitterDone <- true
	}()
	c.LogInfo("HTTP Submitter started")
}

func (c *ScalyrClient) send(buf []byte) {
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
		post, err := http.NewRequest("POST", c.endpoint, bytes.NewReader(buf))
		if err != nil {
			c.LogError("new http error: %s", err)
			return
		}
		post = post.WithContext(ctx)
		post.Header.Set("Content-Type", "application/json")
		post.Header.Set("User-Agent", "dnscollector")
		post.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apikey))

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
			response, err := parseServerResponse(resp.Body)
			if err != nil {
				c.LogError("server returned HTTP status %s (%d), unable to decode response: %e", resp.Status, resp.StatusCode, err)
			} else {
				c.LogError("server returned HTTP status %s (%d), %s", resp.Status, resp.StatusCode, response.Message)
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

func (c *ScalyrClient) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger Scalyr - "+msg, v...)
}

func (c *ScalyrClient) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger Scalyr - "+msg, v...)
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

func (c *ScalyrClient) GetName() string { return c.name }

func (c *ScalyrClient) SetLoggers(loggers []dnsutils.Worker) {}

func (c *ScalyrClient) Channel() chan dnsutils.DnsMessage {
	return c.channel
}
