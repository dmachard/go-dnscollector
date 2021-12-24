package loggers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestWebServerBadBasicAuth(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewWebserver(config, logger.New(false), "dev")

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		statusCode int
	}{
		{
			name:       "total domains",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "total clients",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Loggers.WebServer.BasicAuthLogin, "badpassword")
			responseRecorder := httptest.NewRecorder()

			// call handler
			tc.handler(responseRecorder, request)

			// checking status code
			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}
		})
	}
}

func TestWebServerGet(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewWebserver(config, logger.New(false), "dev")

	// record one dns message to simulate some incoming data
	g.stats.Record(dnsutils.GetFakeDnsMessage())

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		want       string
		statusCode int
	}{
		{
			name:       "total domains",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			want:       config.Subprocessors.Statistics.PromPrefix + `_domains_total{stream="global"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total clients",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			want:       config.Subprocessors.Statistics.PromPrefix + `_requesters_total{stream="global"} 1`,
			statusCode: http.StatusOK,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Loggers.WebServer.BasicAuthLogin, config.Loggers.WebServer.BasicAuthPwd)
			responseRecorder := httptest.NewRecorder()

			// call handler
			tc.handler(responseRecorder, request)

			// checking status code
			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			// checking content
			metrics := strings.TrimSpace(responseRecorder.Body.String())
			if regexp.MustCompile(tc.want).MatchString(string(metrics)) != true {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestWebServerBadMethod(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewWebserver(config, logger.New(false), "dev")

	// record one dns message to simulate some incoming data
	g.stats.Record(dnsutils.GetFakeDnsMessage())

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		statusCode int
	}{
		{
			name:       "metrics",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodPost,
			statusCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Loggers.WebServer.BasicAuthLogin, config.Loggers.WebServer.BasicAuthPwd)
			responseRecorder := httptest.NewRecorder()

			// call handler
			tc.handler(responseRecorder, request)

			// checking status code
			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}
		})
	}
}
