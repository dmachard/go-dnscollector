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
	// init the generator
	g := NewWebserver(dnsutils.GetFakeConfig(), logger.New(false))

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
		{
			name:       "total queries",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "total replies",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "top domains",
			uri:        "/tables/domains",
			handler:    g.tablesDomainsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "top domains",
			uri:        "/tables/domains",
			handler:    g.tablesDomainsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "top clients",
			uri:        "/tables/clients",
			handler:    g.tablesClientsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "top rcodes",
			uri:        "/tables/rcodes",
			handler:    g.tablesRcodesHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "top rrtypes",
			uri:        "/tables/rrtypes",
			handler:    g.tablesRrtypesHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "top operations",
			uri:        "/tables/operations",
			handler:    g.tablesOperationsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth("admin", "badpassword")
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
	// init the generator
	config := dnsutils.GetFakeConfig()
	g := NewWebserver(config, logger.New(false))

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
			want:       config.Generators.WebServer.PrometheusSuffix + `_domains_total 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total clients",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			want:       config.Generators.WebServer.PrometheusSuffix + `_clients_total 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total queries",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			want:       config.Generators.WebServer.PrometheusSuffix + `_queries_total 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total replies",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			want:       config.Generators.WebServer.PrometheusSuffix + `_replies_total 0`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top domains",
			uri:        "/tables/domains",
			handler:    g.tablesDomainsHandler,
			method:     http.MethodGet,
			want:       `\[{"key":"dns.collector","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top domains",
			uri:        "/tables/domains",
			handler:    g.tablesDomainsHandler,
			method:     http.MethodGet,
			want:       `\[{"key":"dns.collector","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top clients",
			uri:        "/tables/clients",
			handler:    g.tablesClientsHandler,
			method:     http.MethodGet,
			want:       `\[{"key":"1.2.3.4","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top rcodes",
			uri:        "/tables/rcodes",
			handler:    g.tablesRcodesHandler,
			method:     http.MethodGet,
			want:       `\[{"key":"NOERROR","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top rrtypes",
			uri:        "/tables/rrtypes",
			handler:    g.tablesRrtypesHandler,
			method:     http.MethodGet,
			want:       `\[{"key":"A","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top operations",
			uri:        "/tables/operations",
			handler:    g.tablesOperationsHandler,
			method:     http.MethodGet,
			want:       `\[{"key":"CLIENT_QUERY","hit":1}]`,
			statusCode: http.StatusOK,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Generators.WebServer.BasicAuthLogin, config.Generators.WebServer.BasicAuthPwd)
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
	// init the generator
	config := dnsutils.GetFakeConfig()
	g := NewWebserver(config, logger.New(false))

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
		{
			name:       "domains",
			uri:        "/tables/domains",
			handler:    g.tablesDomainsHandler,
			method:     http.MethodPost,
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:       "clients",
			uri:        "/tables/clients",
			handler:    g.tablesClientsHandler,
			method:     http.MethodPost,
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:       "rcodes",
			uri:        "/tables/rcodes",
			handler:    g.tablesRcodesHandler,
			method:     http.MethodPost,
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:       "rrtypes",
			uri:        "/tables/rrtypes",
			handler:    g.tablesRrtypesHandler,
			method:     http.MethodPost,
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:       "operations",
			uri:        "/tables/operations",
			handler:    g.tablesOperationsHandler,
			method:     http.MethodPost,
			statusCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Generators.WebServer.BasicAuthLogin, config.Generators.WebServer.BasicAuthPwd)
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
