package dnsutils

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMapttl(t *testing.T) {
	// init map
	mapttl := NewCacheDns(2 * time.Second)

	// Set a new key/value
	mapttl.Set(uint64(1), float64(0))

	// Get value according to the key
	_, ok := mapttl.Get(uint64(1))
	if !ok {
		t.Errorf("key does not exist in the map")
	}
}

func TestMapttlExpire(t *testing.T) {
	// ini map
	mapttl := NewCacheDns(1 * time.Second)

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

func BenchmarkMapSet(b *testing.B) {
	mapexpire := NewCacheDns(10 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), float64(i))
	}
}

func BenchmarkMapDelete(b *testing.B) {

	mapexpire := NewCacheDns(60 * time.Second)

	for i := 0; i < b.N; i++ {
		mapexpire.Set(uint64(i), float64(i))
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mapexpire.Delete(uint64(i))
	}
}

func BenchmarkMapGet(b *testing.B) {
	mapexpire := NewCacheDns(60 * time.Second)

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

func BenchmarkMapConcurrentGet(b *testing.B) {
	mapexpire := NewCacheDns(60 * time.Second)
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
