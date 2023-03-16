package transformers

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func Test_HashQueries(t *testing.T) {
	// init map
	mapttl := NewHashQueries(2 * time.Second)

	// Set a new key/value
	mapttl.Set(uint64(1), float64(0))

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
	mapttl.Set(uint64(1), float64(0))

	// sleep during 2 seconds
	time.Sleep(2 * time.Second)

	// Get value according to the key
	_, ok := mapttl.Get(uint64(1))
	if ok {
		t.Errorf("key/value always in map!")
	}
}

func Benchmark_HashQueries_Set(b *testing.B) {
	mapexpire := NewHashQueries(10 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), float64(i))
	}
}

func Benchmark_HashQueries_Delete(b *testing.B) {
	mapexpire := NewHashQueries(60 * time.Second)

	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), float64(i))
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mapexpire.Delete(uint64(i))
	}
}

func Benchmark_HashQueries_Get(b *testing.B) {
	mapexpire := NewHashQueries(60 * time.Second)

	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), float64(i))
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
		mapexpire.Set(uint64(i), float64(i))
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
