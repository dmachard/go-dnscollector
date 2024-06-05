package pkginit

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type WorkerStats struct {
	Name      string
	Forwarded int
	Dropped   int
}

type TelemetryCollector struct {
	sync.Mutex
	metrics map[string]*prometheus.Desc
	ch      chan WorkerStats
	data    map[string]WorkerStats // To store the worker stats
	stop    chan struct{}          // Channel to signal stopping
}

func NewTelemetryCollector() *TelemetryCollector {
	t := &TelemetryCollector{
		ch:   make(chan WorkerStats),
		data: make(map[string]WorkerStats),
		stop: make(chan struct{}),
	}
	t.metrics = map[string]*prometheus.Desc{
		"forwarded_total": prometheus.NewDesc("forwarded_total", "Total number of forwarded tasks", []string{"name"}, nil),
		"dropped_total":   prometheus.NewDesc("dropped_total", "Total number of dropped tasks", []string{"name"}, nil),
	}
	return t
}

func (t *TelemetryCollector) WaitForStats() {
	for {
		select {
		case ws := <-t.ch:
			t.Lock()
			t.data[ws.Name] = ws
			t.Unlock()
		case <-t.stop:
			// Received stop signal, exit the goroutine
			return
		}
	}
}
func (t *TelemetryCollector) Collect(ch chan<- prometheus.Metric) {
	t.Lock()
	defer t.Unlock()

	// Collect the forwarded and dropped metrics for each worker
	for _, ws := range t.data {
		ch <- prometheus.MustNewConstMetric(
			t.metrics["forwarded_total"],
			prometheus.CounterValue,
			float64(ws.Forwarded),
			ws.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			t.metrics["dropped_total"],
			prometheus.CounterValue,
			float64(ws.Dropped),
			ws.Name,
		)
	}
}

func (t *TelemetryCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range t.metrics {
		ch <- m
	}
}

func (t *TelemetryCollector) Stop() {
	close(t.stop) // Signal the stop channel to stop the goroutine
}
