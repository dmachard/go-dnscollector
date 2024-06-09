package telemetry

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/prometheus/client_golang/prometheus"
)

/*
OpenMetrics and the Prometheus exposition format require the metric name
to consist only of alphanumericals and "_", ":" and they must not start
with digits.
*/
var metricNameRegex = regexp.MustCompile(`_*[^0-9A-Za-z_]+_*`)

func SanitizeMetricName(metricName string) string {
	return metricNameRegex.ReplaceAllString(metricName, "_")
}

type WorkerStats struct {
	Name                 string
	TotalIngress         int
	TotalEgress          int
	TotalForwardedPolicy int
	TotalDroppedPolicy   int
	TotalDiscarded       int
}

type PrometheusCollector struct {
	sync.Mutex
	config     *pkgconfig.Config
	metrics    map[string]*prometheus.Desc
	Record     chan WorkerStats
	data       map[string]WorkerStats // To store the worker stats
	stop       chan struct{}          // Channel to signal stopping
	promPrefix string
}

func NewPrometheusCollector(config *pkgconfig.Config) *PrometheusCollector {
	t := &PrometheusCollector{
		config: config,
		Record: make(chan WorkerStats),
		data:   make(map[string]WorkerStats),
		stop:   make(chan struct{}),
	}

	t.promPrefix = SanitizeMetricName(config.Global.Telemetry.PromPrefix)

	t.metrics = map[string]*prometheus.Desc{
		"worker_ingress_total": prometheus.NewDesc(
			fmt.Sprintf("%s_worker_ingress_traffic_total", t.promPrefix),
			"Ingress traffic associated to each worker", []string{"worker"}, nil),
		"worker_egress_total": prometheus.NewDesc(
			fmt.Sprintf("%s_worker_egress_traffic_total", t.promPrefix),
			"Egress traffic associated to each worker", []string{"worker"}, nil),
		"policy_forwarded_total": prometheus.NewDesc(
			fmt.Sprintf("%s_policy_forwarded_total", t.promPrefix),
			"Total number of forwarded policy", []string{"worker"}, nil),
		"policy_dropped_total": prometheus.NewDesc(
			fmt.Sprintf("%s_policy_dropped_total", t.promPrefix),
			"Total number of dropped policy", []string{"worker"}, nil),
	}
	return t
}

func (t *PrometheusCollector) UpdateStats() {
	for {
		select {
		case ws := <-t.Record:
			t.Lock()
			if _, ok := t.data[ws.Name]; !ok {
				t.data[ws.Name] = ws
			} else {
				updatedWs := t.data[ws.Name]
				updatedWs.TotalForwardedPolicy += ws.TotalForwardedPolicy
				updatedWs.TotalDroppedPolicy += ws.TotalDroppedPolicy
				updatedWs.TotalIngress += ws.TotalIngress
				updatedWs.TotalEgress += ws.TotalEgress
				t.data[ws.Name] = updatedWs
			}
			t.Unlock()
		case <-t.stop:
			// Received stop signal, exit the goroutine
			return
		}
	}
}
func (t *PrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	t.Lock()
	defer t.Unlock()

	// Collect the forwarded and dropped metrics for each worker
	for _, ws := range t.data {
		ch <- prometheus.MustNewConstMetric(
			t.metrics["worker_ingress_total"],
			prometheus.CounterValue,
			float64(ws.TotalIngress),
			ws.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			t.metrics["worker_egress_total"],
			prometheus.CounterValue,
			float64(ws.TotalEgress),
			ws.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			t.metrics["policy_forwarded_total"],
			prometheus.CounterValue,
			float64(ws.TotalForwardedPolicy),
			ws.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			t.metrics["policy_dropped_total"],
			prometheus.CounterValue,
			float64(ws.TotalDroppedPolicy),
			ws.Name,
		)
	}
}

func (t *PrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range t.metrics {
		ch <- m
	}
}

func (t *PrometheusCollector) Stop() {
	close(t.stop) // Signal the stop channel to stop the goroutine
}
