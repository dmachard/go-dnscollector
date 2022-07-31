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

func TestPrometheusGetMetrics(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewPrometheus(config, logger.New(false), "dev", "test")

	// record one dns message to simulate some incoming data
	g.Record(dnsutils.GetFakeDnsMessage())

	tt := []struct {
		name       string
		method     string
		handler    func(w http.ResponseWriter, r *http.Request)
		want       string
		statusCode int
	}{
		{
			name:       "total domains",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_domains_count{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, "/metrics", strings.NewReader(""))
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
