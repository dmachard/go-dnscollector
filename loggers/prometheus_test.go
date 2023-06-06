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

const (
	UDP  = "UDP"
	IPv4 = "IPv4"
)

func TestPrometheus_BadAuth(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewPrometheus(config, logger.New(false), "dev", "test")

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		statusCode int
	}{
		{
			name:       "total clients",
			uri:        "/metrics",
			handler:    g.httpServer.Handler.ServeHTTP,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Loggers.Prometheus.BasicAuthLogin, "badpassword")
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

func TestPrometheus_GetMetrics(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	config.Loggers.Prometheus.HistogramMetricsEnabled = true
	g := NewPrometheus(config, logger.New(false), "dev", "test")

	// record one dns message to simulate some incoming data
	noerror_record := dnsutils.GetFakeDnsMessage()
	noerror_record.DNS.Type = dnsutils.DnsQuery
	noerror_record.PublicSuffix = &dnsutils.TransformPublicSuffix{
		QnamePublicSuffix: "faketld",
	}
	noerror_record.DNS.Flags.AA = true
	noerror_record.DnsTap.Latency = 0.05
	noerror_record.NetworkInfo.Protocol = UDP
	noerror_record.NetworkInfo.Family = IPv4
	noerror_record.DNS.Length = 123

	g.Record(noerror_record)

	// compute metrics, this function is called every second
	g.ComputeEventsPerSecond()

	nx_record := dnsutils.GetFakeDnsMessage()
	nx_record.DNS.Type = dnsutils.DnsReply
	nx_record.DNS.Rcode = dnsutils.DNS_RCODE_NXDOMAIN
	nx_record.NetworkInfo.Protocol = UDP
	nx_record.NetworkInfo.Family = IPv4
	nx_record.DNS.Length = 123

	// nx_record.PublicSuffix = &dnsutils.TransformPublicSuffix{
	// 	QnamePublicSuffix: "faketld1",
	// }
	g.Record(nx_record)

	sf_record := dnsutils.GetFakeDnsMessage()
	sf_record.DNS.Type = dnsutils.DnsReply
	sf_record.DNS.Rcode = dnsutils.DNS_RCODE_SERVFAIL
	sf_record.NetworkInfo.Protocol = UDP
	sf_record.NetworkInfo.Family = IPv4
	sf_record.DNS.Length = 123

	g.Record(sf_record)

	// call ComputeMetrics for the second time, to calculate per-second metrcis
	g.ComputeEventsPerSecond()

	tt := []struct {
		name       string
		method     string
		handler    func(w http.ResponseWriter, r *http.Request)
		want       string
		statusCode int
	}{
		{
			name:       "total bytes",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_bytes_total{stream_id="collector"} 369`, // We send 3 msgs, fake msg is of 123
			statusCode: http.StatusOK,
		},
		{
			name:       "total received bytes",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_received_bytes_total{stream_id="collector"} 123`, // We send 3 msgs, fake msg is of 123
			statusCode: http.StatusOK,
		},
		{
			name:       "total sent bytes",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_sent_bytes_total{stream_id="collector"} 246`, // We send 3 msgs, fake msg is of 123
			statusCode: http.StatusOK,
		},
		{
			name:       "top domains",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_top_domains{domain="dns.collector",stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top NX domains",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_top_nxdomains{domain="dns.collector",stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "top SF domains",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_top_sfdomains{domain="dns.collector",stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "EPS counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_throughput_ops{stream_id="collector"} 2`,
			statusCode: http.StatusOK,
		},
		{
			name:       "TLD counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_tlds_total{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "Requesters counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_requesters_total{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total domains",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_domains_total{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total requesters",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_requesters_total{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total nxdomain",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_nxdomains_total{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total sfdomain",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_sfdomains_total{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total dns messages",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_dnsmessages_total{stream_id="collector"} 3`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total queries",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_queries_total{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total replies",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_replies_total{stream_id="collector"} 2`,
			statusCode: http.StatusOK,
		},
		{
			name:       "total qtypes counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_qtypes_total{query_type="A",stream_id="collector"} 3`,
			statusCode: http.StatusOK,
		},
		{
			name:       "messages with AA Flag counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_flag_aa_total{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:    "UDP total requests counter",
			method:  http.MethodGet,
			handler: g.httpServer.Handler.ServeHTTP,
			// For some reason labels go in a different order, compared to one used in Collect()
			want:       config.Loggers.Prometheus.PromPrefix + `_ipprotocol_total{net_transport="UDP",stream_id="collector"} 3`,
			statusCode: http.StatusOK,
		},
		{
			name:    "IPv4 total requests counter",
			method:  http.MethodGet,
			handler: g.httpServer.Handler.ServeHTTP,
			// For some reason labels go in a different order, compared to one used in Collect()
			want:       config.Loggers.Prometheus.PromPrefix + `_ipversion_total{net_family="IPv4",stream_id="collector"} 3`,
			statusCode: http.StatusOK,
		},
		{
			name:       "Latencies count",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_latencies_count{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "Latency Bucket 0.001",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_latencies_bucket{stream_id="collector",le="0.001"} 0`,
			statusCode: http.StatusOK,
		},
		{
			name:       "Latency Bucket 0.1",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_latencies_bucket{stream_id="collector",le="0.1"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "Latency Bucket +Inf",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_latencies_bucket{stream_id="collector",le="\+Inf"} 1`,
			statusCode: http.StatusOK,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, "/metrics", strings.NewReader(""))
			request.SetBasicAuth(config.Loggers.Prometheus.BasicAuthLogin, config.Loggers.Prometheus.BasicAuthPwd)
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

// Test that EPS (Events Per Second) Counters increment correctly
func TestPrometheus_EPS_Counters(t *testing.T) {
	// init the logger
	config := dnsutils.GetFakeConfig()
	g := NewPrometheus(config, logger.New(false), "dev", "test")

	tt_0 := []tEPSTestCase{
		{
			name:       "EPS counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_throughput_ops{stream_id="collector"} 0`,
			statusCode: http.StatusOK,
		},
	}
	tt_1 := []tEPSTestCase{
		{
			name:       "EPS counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_throughput_ops{stream_id="collector"} 2`,
			statusCode: http.StatusOK,
		},
		{
			name:       "EPS counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_throughput_ops_max{stream_id="collector"} 2`,
			statusCode: http.StatusOK,
		},
	}
	tt_2 := []tEPSTestCase{
		{
			name:       "EPS counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_throughput_ops{stream_id="collector"} 1`,
			statusCode: http.StatusOK,
		},
		{
			name:       "EPS counter",
			method:     http.MethodGet,
			handler:    g.httpServer.Handler.ServeHTTP,
			want:       config.Loggers.Prometheus.PromPrefix + `_throughput_ops_max{stream_id="collector"} 2`,
			statusCode: http.StatusOK,
		},
	}

	// record one dns message to simulate some incoming data
	noerror_record := dnsutils.GetFakeDnsMessage()
	noerror_record.DNS.Type = dnsutils.DnsQuery
	g.Record(noerror_record)
	// Zero second elapsed, initalize EPS
	g.ComputeEventsPerSecond()

	for _, tc := range tt_0 {
		validateEPSCaseHelper(t, config, tc)
	}

	// Simulate processing 2 more messages, that will be 2 events per second
	// after next ComputeEventsPerSecond call
	g.Record(noerror_record)
	g.Record(noerror_record)
	g.ComputeEventsPerSecond()

	for _, tc := range tt_1 {
		validateEPSCaseHelper(t, config, tc)
	}

	// During next 'second' we see only 1 event. EPS counter changes, EPS Max counter keeps it's value
	g.Record(noerror_record)
	g.ComputeEventsPerSecond()

	for _, tc := range tt_2 {
		validateEPSCaseHelper(t, config, tc)
	}

}

type tEPSTestCase struct {
	name       string
	method     string
	handler    func(w http.ResponseWriter, r *http.Request)
	want       string
	statusCode int
}

func validateEPSCaseHelper(t *testing.T, config *dnsutils.Config, tc tEPSTestCase) {
	t.Run(tc.name, func(t *testing.T) {
		// init httptest
		request := httptest.NewRequest(tc.method, "/metrics", strings.NewReader(""))
		request.SetBasicAuth(config.Loggers.Prometheus.BasicAuthLogin, config.Loggers.Prometheus.BasicAuthPwd)
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
