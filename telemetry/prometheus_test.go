package telemetry

import (
	"testing"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/stretchr/testify/assert"
)

func TestTelemetry_SanitizeMetricName(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"metric:name", "metric_name"},
		{"metric-name", "metric_name"},
		{"metric.name", "metric_name"},
	}

	for _, tc := range testCases {
		actual := SanitizeMetricName(tc.input)
		assert.Equal(t, tc.expected, actual)
	}
}

func TestTelemetry_PrometheusCollectorUpdateStats(t *testing.T) {
	config := pkgconfig.Config{}

	collector := NewPrometheusCollector(&config)

	// Create a sample WorkerStats
	ws := WorkerStats{
		Name:         "worker1",
		TotalIngress: 10, TotalEgress: 5,
		TotalForwardedPolicy: 2, TotalDroppedPolicy: 1, TotalDiscarded: 3,
	}

	// Send the stats to the collector
	go collector.UpdateStats()
	collector.Record <- ws

	// Verify that the stats were updated
	storedWS, ok := collector.GetWorkerStats("worker1")
	assert.True(t, ok, "Worker stats should be present in the collector")
	assert.Equal(t, ws.TotalIngress, storedWS.TotalIngress)
	assert.Equal(t, ws.TotalEgress, storedWS.TotalEgress)
	assert.Equal(t, ws.TotalForwardedPolicy, storedWS.TotalForwardedPolicy)
	assert.Equal(t, ws.TotalDroppedPolicy, storedWS.TotalDroppedPolicy)
	assert.Equal(t, ws.TotalDiscarded, storedWS.TotalDiscarded)
}
