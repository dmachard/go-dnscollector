package telemetry

import (
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
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
		"worker_discarded_total": prometheus.NewDesc(
			fmt.Sprintf("%s_worker_discarded_traffic_total", t.promPrefix),
			"Discarded traffic associated to each worker", []string{"worker"}, nil),
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
				updatedWs.TotalDiscarded += ws.TotalDiscarded
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
			t.metrics["worker_discarded_total"],
			prometheus.CounterValue,
			float64(ws.TotalDiscarded),
			ws.Name,
		)
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

func InitTelemetryServer(config *pkgconfig.Config, logger *logger.Logger) (*http.Server, *PrometheusCollector, chan error) {
	// channel for error
	errChan := make(chan error)

	// HTTP server
	promServer := &http.Server{
		Addr:              config.Global.Telemetry.WebListen,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Prometheus collectors
	metrics := NewPrometheusCollector(config)

	if config.Global.Telemetry.Enabled {
		go func() {
			// start metrics
			go metrics.UpdateStats()

			// register metrics
			prometheus.MustRegister(metrics)
			prometheus.MustRegister(version.NewCollector(config.Global.Telemetry.PromPrefix))

			// handle /metrics
			http.Handle(config.Global.Telemetry.WebPath, promhttp.Handler())

			// handle http error
			http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
				_, err := w.Write([]byte(`<html>
                    <head><title>DNScollector Exporter</title></head>
                    <body>
                    <h1>DNScollector Exporter</h1>
                    <p><a href='` + config.Global.Telemetry.WebPath + `'>Metrics</a></p>
                    </body>
                    </html>`))
				if err != nil {
					errChan <- err
				}
			})

			// start http server
			if err := promServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errChan <- err
			}
		}()
	}

	return promServer, metrics, errChan
}
