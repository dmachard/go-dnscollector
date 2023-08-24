package loggers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
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

	// By default, prometheus uses 'stream_id' as the label
	// t.Run("SingleLabelStreamID", getMetricsTestCase(config, map[string]string{"stream_id": "collector"}))

	config.Loggers.Prometheus.LabelsList = []string{"resolver", "stream_id"}
	t.Run("TwoLabelsStreamIDResolver", getMetricsTestCase(config, map[string]string{"resolver": "4.3.2.1", "stream_id": "collector"}))
}

// This helper generates a set of DNS packes for logger to count
// It then collects Prometheus metrics to verify they exist and have expected labels/values
// func getMetricsHelper(config *dnsutils.Config, labels map[string]string, t *testing.T) {
func getMetricsTestCase(config *dnsutils.Config, labels map[string]string) func(t *testing.T) {
	return func(t *testing.T) {
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

		// Generate records for a different stream id
		noerror_record.DnsTap.Identity = "other_collector"
		g.Record(noerror_record)

		// call ComputeMetrics for the second time, to calculate per-second metrcis
		g.ComputeEventsPerSecond()
		mf := getMetrics(g, t)
		ensureMetricValue(t, mf, "dnscollector_bytes_total", labels, 369)
		ensureMetricValue(t, mf, "dnscollector_received_bytes_total", labels, 123)
		ensureMetricValue(t, mf, "dnscollector_sent_bytes_total", labels, 246)

		ensureMetricValue(t, mf, "dnscollector_throughput_ops", labels, 2)
		ensureMetricValue(t, mf, "dnscollector_tlds_total", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_requesters_total", labels, 1)

		ensureMetricValue(t, mf, "dnscollector_domains_total", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_domains_domains_total", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_nxdomains_total", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_sfdomains_total", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_dnsmessages_total", labels, 3)
		ensureMetricValue(t, mf, "dnscollector_queries_total", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_replies_total", labels, 2)
		ensureMetricValue(t, mf, "dnscollector_flag_aa_total", labels, 1)

		labels["domain"] = "dns.collector"
		ensureMetricValue(t, mf, "dnscollector_top_domains", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_top_nxdomains", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_top_sfdomains", labels, 1)

		delete(labels, "domain")
		labels["query_type"] = "A"
		ensureMetricValue(t, mf, "dnscollector_qtypes_total", labels, 3)
		delete(labels, "query_type")
		labels["net_transport"] = "UDP"
		ensureMetricValue(t, mf, "dnscollector_ipprotocol_total", labels, 3)
		delete(labels, "net_transport")
		labels["net_family"] = "IPv4"
		ensureMetricValue(t, mf, "dnscollector_ipversion_total", labels, 3)
		delete(labels, "net_family")
		ensureMetricValue(t, mf, "dnscollector_latencies_count", labels, 1)
		labels["le"] = "0.001"
		ensureMetricValue(t, mf, "dnscollector_latencies_bucket", labels, 0)
		labels["le"] = "0.1"
		ensureMetricValue(t, mf, "dnscollector_latencies_bucket", labels, 1)
		labels["le"] = "+Inf"
		ensureMetricValue(t, mf, "dnscollector_latencies_bucket", labels, 1)
	}
}

// Test that EPS (Events Per Second) Counters increment correctly
func TestPrometheus_EPS_Counters(t *testing.T) {
	config := dnsutils.GetFakeConfig()
	g := NewPrometheus(config, logger.New(false), "dev", "test")

	// record one dns message to simulate some incoming data
	noerror_record := dnsutils.GetFakeDnsMessage()
	noerror_record.DNS.Type = dnsutils.DnsQuery
	g.Record(noerror_record)
	// Zero second elapsed, initalize EPS
	g.ComputeEventsPerSecond()
	mf := getMetrics(g, t)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops", map[string]string{"stream_id": "collector"}, 0)

	// Simulate processing 2 more messages, that will be 2 events per second
	// after next ComputeEventsPerSecond call
	g.Record(noerror_record)
	g.Record(noerror_record)
	g.ComputeEventsPerSecond()
	mf = getMetrics(g, t)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops", map[string]string{"stream_id": "collector"}, 2)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops_max", map[string]string{"stream_id": "collector"}, 2)

	// for _, tc := range tt_1 {
	// 	validateEPSCaseHelper(t, config, tc)
	// }

	// During next 'second' we see only 1 event. EPS counter changes, EPS Max counter keeps it's value
	g.Record(noerror_record)
	g.ComputeEventsPerSecond()

	mf = getMetrics(g, t)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops", map[string]string{"stream_id": "collector"}, 1)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops_max", map[string]string{"stream_id": "collector"}, 2)

	// for _, tc := range tt_2 {
	// 	validateEPSCaseHelper(t, config, tc)
	// }

}

func TestPrometheus_BuildInfo(t *testing.T) {
	config := dnsutils.GetFakeConfig()
	// config.Loggers.Prometheus.HistogramMetricsEnabled = true
	g := NewPrometheus(config, logger.New(false), "dev", "test")

	mf := getMetrics(g, t)

	if !ensureMetricValue(t, mf, "dnscollector_build_info", map[string]string{}, 1) {
		t.Errorf("Cannot validate build info!")
	}

}

func TestPrometheus_ConfirmDifferentResolvers(t *testing.T) {
	config := dnsutils.GetFakeConfig()
	config.Loggers.Prometheus.LabelsList = []string{"resolver"}
	g := NewPrometheus(config, logger.New(false), "dev", "test")
	noerror_record := dnsutils.GetFakeDnsMessage()
	noerror_record.DNS.Length = 123
	noerror_record.NetworkInfo.ResponseIp = "1.2.3.4"
	g.Record(noerror_record)
	noerror_record.DNS.Length = 999
	noerror_record.NetworkInfo.ResponseIp = "10.10.10.10"
	g.Record(noerror_record)
	mf := getMetrics(g, t)

	ensureMetricValue(t, mf, "dnscollector_bytes_total", map[string]string{"resolver": "1.2.3.4"}, 123)
	ensureMetricValue(t, mf, "dnscollector_bytes_total", map[string]string{"resolver": "10.10.10.10"}, 999)
}

func ensureMetricValue(t *testing.T, mf map[string]*dto.MetricFamily, name string, labels map[string]string, value float64) bool {
	m, found := mf[name]
	if !found {
		return false
	}
	// Match labels
	for _, metric := range m.Metric {
		unmatched := len(labels)
	LBL:
		for _, lp := range metric.GetLabel() {
			if val, ok := labels[*lp.Name]; ok {
				if val == *lp.Value {
					unmatched--
				} else {
					break LBL
				}
			}
		}
		// check if we found the metric we wanted
		if unmatched == 0 {
			var pv float64
			switch m.GetType() {
			case dto.MetricType_COUNTER:
				pv = metric.GetCounter().GetValue()
				if pv == value {
					return true
				}
			case dto.MetricType_GAUGE:
				pv = metric.GetGauge().GetValue()
				if pv == value {
					return true
				}
			}
			t.Errorf("Metric %v, expected=%v, got=%v", name, value, pv)
		}
	}
	t.Errorf("Not found metric %v{%v}", name, labels)
	return false
}

func getMetrics(prom *Prometheus, t *testing.T) map[string]*dto.MetricFamily {

	request := httptest.NewRequest(http.MethodGet, "/metrics", strings.NewReader(""))
	request.SetBasicAuth(prom.config.Loggers.Prometheus.BasicAuthLogin, prom.config.Loggers.Prometheus.BasicAuthPwd)
	responseRecorder := httptest.NewRecorder()

	// call handler
	prom.httpServer.Handler.ServeHTTP(responseRecorder, request)

	// checking status code
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
	}

	var parser expfmt.TextParser
	mf, err := parser.TextToMetricFamilies(responseRecorder.Body)
	if err != nil {
		t.Fatalf("Error parsing prom metrics: %v", err)
	}
	return mf
}
