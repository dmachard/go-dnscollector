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

func TestRestAPIBadBasicAuth(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewRestAPI(config, logger.New(false), "dev", "test")

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		statusCode int
	}{
		{
			name:       "get clients",
			uri:        "/clients",
			handler:    g.GetClientsHandler,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "get clients",
			uri:        "/reset",
			handler:    g.GetClientsHandler,
			method:     http.MethodDelete,
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Loggers.RestAPI.BasicAuthLogin, "badpassword")
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
	g := NewRestAPI(config, logger.New(false), "dev", "test")

	// record one dns message to simulate some incoming data
	dm := dnsutils.GetFakeDnsMessage()
	dm.PublicSuffix = &dnsutils.PublicSuffix{
		QnamePublicSuffix:        "-",
		QnameEffectiveTLDPlusOne: "-",
	}
	dm.PublicSuffix.QnamePublicSuffix = "collector"

	// record the dns message
	g.RecordDnsMessage(dm)

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		want       string
		statusCode int
	}{
		{
			name:       "get clients",
			uri:        "/clients",
			handler:    g.GetClientsHandler,
			method:     http.MethodGet,
			want:       `{"1.2.3.4":1}`,
			statusCode: http.StatusOK,
		},
		{
			name:       "post clients refused",
			uri:        "/clients",
			handler:    g.GetClientsHandler,
			method:     http.MethodPost,
			want:       "Method not allowed",
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:       "get tlds",
			uri:        "/tlds",
			handler:    g.GetTLDsHandler,
			method:     http.MethodGet,
			want:       `{"collector":1}`,
			statusCode: http.StatusOK,
		},
		{
			name:       "post tlds refused",
			uri:        "/tlds",
			handler:    g.GetTLDsHandler,
			method:     http.MethodPost,
			want:       `Method not allowed`,
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:       "get domains",
			uri:        "/domains",
			handler:    g.GetDomainsHandler,
			method:     http.MethodGet,
			want:       `{"dns.collector":1}`,
			statusCode: http.StatusOK,
		},
		{
			name:       "post domains refused",
			uri:        "/domains",
			handler:    g.GetDomainsHandler,
			method:     http.MethodPost,
			want:       `Method not allowed`,
			statusCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Loggers.RestAPI.BasicAuthLogin, config.Loggers.RestAPI.BasicAuthPwd)
			responseRecorder := httptest.NewRecorder()

			// call handler
			tc.handler(responseRecorder, request)

			// checking status code
			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			// checking content
			metrics := strings.TrimSpace(responseRecorder.Body.String())
			if regexp.MustCompile(tc.want).MatchString(metrics) != true {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}
