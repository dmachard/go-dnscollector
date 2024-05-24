package transformers

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestLatency_MeasureLatency(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	outChannels := []chan dnsutils.DNSMessage{}

	// init transformer
	latency := NewLatencyTransform(config, logger.New(true), "test", 0, outChannels)
	latency.GetTransforms()

	testcases := []struct {
		name string
		cq   string
		cr   string
	}{
		{
			name: "standard_mode",
			cq:   dnsutils.DNSQuery,
			cr:   dnsutils.DNSReply,
		},
		{
			name: "quiet_mode",
			cq:   dnsutils.DNSQueryQuiet,
			cr:   dnsutils.DNSReplyQuiet,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Register Query
			CQ := dnsutils.GetFakeDNSMessage()
			CQ.DNS.Type = tc.cq
			CQ.DNSTap.Timestamp = 1704486841216166066

			// Measure latency
			latency.measureLatency(&CQ)

			// Register Query
			CR := dnsutils.GetFakeDNSMessage()
			CR.DNS.Type = tc.cr
			CR.DNSTap.Timestamp = 1704486841227961611

			// Measure latency
			latency.measureLatency(&CR)

			if CR.DNSTap.Latency == 0.0 {
				t.Errorf("incorrect latency, got 0.0")
			}
		})
	}
}

func TestLatency_DetectEvictedTimeout(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Latency.Enable = true
	config.Latency.QueriesTimeout = 1

	outChannels := []chan dnsutils.DNSMessage{}
	outChannels = append(outChannels, make(chan dnsutils.DNSMessage, 1))

	// init transformer
	latency := NewLatencyTransform(config, logger.New(true), "test", 0, outChannels)
	latency.GetTransforms()

	testcases := []struct {
		name string
		cq   string
		cr   string
	}{
		{
			name: "standard_mode",
			cq:   dnsutils.DNSQuery,
			cr:   dnsutils.DNSReply,
		},
		{
			name: "quiet_mode",
			cq:   dnsutils.DNSQueryQuiet,
			cr:   dnsutils.DNSReplyQuiet,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Register Query
			CQ := dnsutils.GetFakeDNSMessage()
			CQ.DNS.Type = tc.cq
			CQ.DNSTap.Timestamp = 1704486841216166066

			// Measure latency
			latency.detectEvictedTimeout(&CQ)

			time.Sleep(2 * time.Second)

			dmTimeout := <-outChannels[0]
			if dmTimeout.DNS.Rcode != "TIMEOUT" {
				t.Errorf("incorrect rcode, expected=TIMEOUT, got=%s", dmTimeout.DNS.Rcode)
			}
		})
	}
}

func Test_HashQueries(t *testing.T) {
	// init map
	mapttl := NewHashQueries(2 * time.Second)

	// Set a new key/value
	mapttl.Set(uint64(1), int64(0))

	// Get value according to the key
	_, ok := mapttl.Get(uint64(1))
	if !ok {
		t.Errorf("key does not exist in the map")
	}
}

func Test_HashQueries_Expire(t *testing.T) {
	// ini map
	mapttl := NewHashQueries(1 * time.Second)

	// Set a new key/value
	mapttl.Set(uint64(1), int64(0))

	// sleep during 2 seconds
	time.Sleep(2 * time.Second)

	// Get value according to the key
	_, ok := mapttl.Get(uint64(1))
	if ok {
		t.Errorf("key/value always in map!")
	}
}

// Bench
func Benchmark_HashQueries_Set(b *testing.B) {
	mapexpire := NewHashQueries(10 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), int64(i))
	}
}

func Benchmark_HashQueries_Delete(b *testing.B) {
	mapexpire := NewHashQueries(60 * time.Second)

	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), int64(i))
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mapexpire.Delete(uint64(i))
	}
}

func Benchmark_HashQueries_Get(b *testing.B) {
	mapexpire := NewHashQueries(60 * time.Second)

	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), int64(i))
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, ok := mapexpire.Get(uint64(i))
		if !ok {
			break
		}

	}
}

func Benchmark_HashQueries_ConcurrentGet(b *testing.B) {
	mapexpire := NewHashQueries(60 * time.Second)
	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), int64(i))
	}

	var wg sync.WaitGroup
	b.ResetTimer()

	for wc := 0; wc < runtime.NumCPU(); wc++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				_, ok := mapexpire.Get(uint64(i))
				if !ok {
					break
				}
			}
		}(b.N)
	}

	wg.Wait()
}
