package generators

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

func GetLogger() *logger.Logger {
	logger := logger.New(false)
	return logger
}

func GetFakeConfig() *common.Config {
	config := &common.Config{}
	return config
}

func GetFakeDnsMessage() dnsmessage.DnsMessage {
	dm := dnsmessage.DnsMessage{}
	dm.Init()
	dm.Operation = "CLIENT_QUERY"
	dm.Type = "query"
	dm.Qname = "dns.collector"
	dm.QueryIp = "1.2.3.4"
	dm.Rcode = "NOERROR"
	dm.Qtype = "A"
	return dm
}

func TestWebServerGet(t *testing.T) {
	// init the generator
	g := NewWebserver(GetFakeConfig(), GetLogger())

	// record one dns message to simulate some incoming data
	g.stats.Record(GetFakeDnsMessage())

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		body       string
		want       string
		statusCode int
	}{
		{
			name:       "total domains",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `dnscollector_domains_total 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total clients",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `dnscollector_clients_total 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total queries",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `dnscollector_queries_total 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total replies",
			uri:        "/metrics",
			handler:    g.metricsHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `dnscollector_replies_total 0`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top domains",
			uri:        "/tables/domains",
			handler:    g.tablesDomainsHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `\[{"key":"dns.collector","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top domains",
			uri:        "/tables/domains",
			handler:    g.tablesDomainsHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `\[{"key":"dns.collector","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top clients",
			uri:        "/tables/clients",
			handler:    g.tablesClientsHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `\[{"key":"1.2.3.4","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top rcodes",
			uri:        "/tables/rcodes",
			handler:    g.tablesRcodesHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `\[{"key":"NOERROR","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top rrtypes",
			uri:        "/tables/rrtypes",
			handler:    g.tablesRrtypesHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `\[{"key":"A","hit":1}]`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top operations",
			uri:        "/tables/operations",
			handler:    g.tablesOperationsHandler,
			method:     http.MethodGet,
			body:       "",
			want:       `\[{"key":"CLIENT_QUERY","hit":1}]`,
			statusCode: http.StatusOK,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
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
	g := NewWebserver(GetFakeConfig(), GetLogger())

	// record one dns message to simulate some incoming data
	g.stats.Record(GetFakeDnsMessage())

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
