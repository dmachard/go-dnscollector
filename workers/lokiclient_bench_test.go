package workers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
)

func Benchmark_LokiClient_RelabelInput_Selective(b *testing.B) {
	dm := dnsutils.GetFakeDNSMessage()
	flat, err := dm.Flatten()
	if err != nil {
		b.Fatal(err)
	}

	cfg := config.GetDefaultConfig()
	cfg.Loggers.LokiClient.RelabelConfigs = []*relabel.Config{
		{
			Action:       relabel.Replace,
			Regex:        relabel.MustNewRegexp("(.*)"),
			Replacement:  "$1",
			SourceLabels: model.LabelNames{"__dns_qname"},
			TargetLabel:  "qname",
		},
	}
	client := NewLokiClient(cfg, logger.New(false), "bench")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		finalSet := []labels.Label{
			{Name: "identity", Value: dm.DNSTap.Identity},
			{Name: "job", Value: "dnscollector"},
		}
		_ = client.relabelInput(flat, finalSet)
	}
}

func Benchmark_LokiClient_RelabelInput_AllLabels(b *testing.B) {
	dm := dnsutils.GetFakeDNSMessage()
	flat, err := dm.Flatten()
	if err != nil {
		b.Fatal(err)
	}

	cfg := config.GetDefaultConfig()
	cfg.Loggers.LokiClient.RelabelConfigs = []*relabel.Config{
		{
			Action:      relabel.LabelMap,
			Regex:       relabel.MustNewRegexp("__dns_(.*)"),
			Replacement: "$1",
		},
	}
	client := NewLokiClient(cfg, logger.New(false), "bench")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		finalSet := []labels.Label{
			{Name: "identity", Value: dm.DNSTap.Identity},
			{Name: "job", Value: "dnscollector"},
		}
		_ = client.relabelInput(flat, finalSet)
	}
}

func benchmarkLokiClientThroughput(b *testing.B, sinkDelay time.Duration, batchSize int, chanSize int) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if sinkDelay > 0 {
			time.Sleep(sinkDelay)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := config.GetDefaultConfig()
	cfg.Loggers.LokiClient.ServerURL = server.URL + "/loki/api/v1/push"
	cfg.Loggers.LokiClient.BatchSize = batchSize
	cfg.Loggers.LokiClient.FlushInterval = 60
	if chanSize > 0 {
		cfg.Global.Worker.ChannelBufferSize = chanSize
	}

	w := NewLokiClient(cfg, logger.New(false), "bench-lokiclient")
	go w.StartCollect()
	defer func() {
		go func() {
			for range w.GetInputChannel() {
			}
		}()
		w.Stop()
	}()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "dnscollector.dev"
	dm.DNSTap.Identity = "bench"

	inChan := w.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		batch := dnsutils.NewDNSMessageBatch(&msg)
		inChan <- batch
	}
}

func Benchmark_LokiClient_Throughput_FastSink(b *testing.B) {
	benchmarkLokiClientThroughput(b, 0, 100*100, 256)
}

func Benchmark_LokiClient_Throughput_SlowSink_1ms(b *testing.B) {
	benchmarkLokiClientThroughput(b, 1*time.Millisecond, 100*100, 256)
}

func Benchmark_LokiClient_Throughput_SlowSink_5ms(b *testing.B) {
	benchmarkLokiClientThroughput(b, 5*time.Millisecond, 100*100, 256)
}

func Benchmark_LokiClient_Throughput_SlowSink_FlushEveryMsg(b *testing.B) {
	benchmarkLokiClientThroughput(b, 1*time.Millisecond, 0, 64)
}
