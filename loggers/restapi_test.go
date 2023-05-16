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

func TestRestAPI_BadBasicAuth(t *testing.T) {
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

func TestRestAPI_MethodNotAllowed(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewRestAPI(config, logger.New(false), "dev", "test")

	// record one dns message to simulate some incoming data
	dm := dnsutils.GetFakeDnsMessage()
	dm.PublicSuffix = &dnsutils.TransformPublicSuffix{
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
			name:       "post streams refused",
			uri:        "/streams",
			handler:    g.GetStreamsHandler,
			method:     http.MethodPost,
			want:       `Method not allowed`,
			statusCode: http.StatusMethodNotAllowed,
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
			name:       "post tlds refused",
			uri:        "/tlds",
			handler:    g.GetTLDsHandler,
			method:     http.MethodPost,
			want:       `Method not allowed`,
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:       "post domains refused",
			uri:        "/domains",
			handler:    g.GetDomainsHandler,
			method:     http.MethodPost,
			want:       `Method not allowed`,
			statusCode: http.StatusMethodNotAllowed,
		},
		{
			name:       "post search refused",
			uri:        "/search",
			handler:    g.GetSearchHandler,
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

func TestRestAPI_GetMethod(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewRestAPI(config, logger.New(false), "dev", "test")

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		want       string
		dm         dnsutils.DnsMessage
		dmRcode    string
		statusCode int
	}{
		{
			name:       "streams",
			uri:        "/streams",
			handler:    g.GetStreamsHandler,
			method:     http.MethodGet,
			want:       `\[\{"key":"collector","hit":1\}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
		{
			name:       "clients",
			uri:        "/clients",
			handler:    g.GetClientsHandler,
			method:     http.MethodGet,
			want:       `\[\{"key":"1.2.3.4","hit":2\}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
		{
			name:       "domains",
			uri:        "/domains",
			handler:    g.GetDomainsHandler,
			method:     http.MethodGet,
			want:       `\[\{"key":"dns.collector","hit":3\}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
		{
			name:       "nx domains",
			uri:        "/domains/nx",
			handler:    g.GetNxDomainsHandler,
			method:     http.MethodGet,
			want:       `\[\{"key":"dns.collector","hit":1\}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NXDOMAIN",
		},
		{
			name:       "servfail domains",
			uri:        "/domains/servfail",
			handler:    g.GetSfDomainsHandler,
			method:     http.MethodGet,
			want:       `\[\{"key":"dns.collector","hit":1\}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "SERVFAIL",
		},
		{
			name:       "tlds",
			uri:        "/tlds",
			handler:    g.GetTLDsHandler,
			method:     http.MethodGet,
			want:       `\[\{"key":".com","hit":1\}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
		{
			name:       "suspicious",
			uri:        "/suspicious",
			handler:    g.GetSuspiciousHandler,
			method:     http.MethodGet,
			want:       `\[\{"score":1,"malformed-pkt":false,"large-pkt":false,"long-domain":false,"slow-domain":false,"unallowed-chars":false,"uncommon-qtypes":false,"excessive-number-labels":false,"domain":"dns:collector"\}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
		{
			name:       "reset",
			uri:        "/reset",
			handler:    g.DeleteResetHandler,
			method:     http.MethodDelete,
			want:       `OK`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
		{
			name:       "search_by_domain",
			uri:        "/search?filter=dns.collector",
			handler:    g.GetSearchHandler,
			method:     http.MethodGet,
			want:       `\[\{"key":"1.2.3.4","hit":1\}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
		{
			name:       "search_by_ip",
			uri:        "/search?filter=1.2.3.4",
			handler:    g.GetSearchHandler,
			method:     http.MethodGet,
			want:       `\[\{"key":"dns.collector","hit":2}\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
		{
			name:       "search_not_found",
			uri:        "/search?filter=notfound.collector",
			handler:    g.GetSearchHandler,
			method:     http.MethodGet,
			want:       `\[\]`,
			statusCode: http.StatusOK,
			dm:         dnsutils.GetFakeDnsMessage(),
			dmRcode:    "NOERROR",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// record the dns message
			dm := tc.dm
			dm.DNS.Rcode = tc.dmRcode
			if tc.name == "tlds" {
				dm.PublicSuffix = &dnsutils.TransformPublicSuffix{}
				dm.PublicSuffix.QnamePublicSuffix = ".com"
			}

			if tc.name == "suspicious" {
				dm.DNS.Qname = "dns:collector"
				dm.Suspicious = &dnsutils.TransformSuspicious{Score: 1}
			}
			g.RecordDnsMessage(dm)

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
			response := strings.TrimSpace(responseRecorder.Body.String())
			if regexp.MustCompile(tc.want).MatchString(response) != true {
				t.Errorf("Want '%s', got '%s'", tc.want, response)
			}
		})
	}
}
