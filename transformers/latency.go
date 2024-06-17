package transformers

import (
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

// queries map
type MapQueries struct {
	sync.RWMutex
	ttl      time.Duration
	kv       map[uint64]dnsutils.DNSMessage
	channels []chan dnsutils.DNSMessage
}

func NewMapQueries(ttl time.Duration, channels []chan dnsutils.DNSMessage) MapQueries {
	return MapQueries{
		ttl:      ttl,
		kv:       make(map[uint64]dnsutils.DNSMessage),
		channels: channels,
	}
}

func (mp *MapQueries) SetTTL(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *MapQueries) Exists(key uint64) (ok bool) {
	mp.RLock()
	defer mp.RUnlock()
	_, ok = mp.kv[key]
	return ok
}

func (mp *MapQueries) Set(key uint64, dm dnsutils.DNSMessage) {
	mp.Lock()
	defer mp.Unlock()
	mp.kv[key] = dm
	time.AfterFunc(mp.ttl, func() {
		if mp.Exists(key) {
			dm.DNS.Rcode = "TIMEOUT"
			for i := range mp.channels {
				mp.channels[i] <- dm
			}
		}
		mp.Delete(key)
	})
}

func (mp *MapQueries) Delete(key uint64) {
	mp.Lock()
	defer mp.Unlock()
	delete(mp.kv, key)
}

// hash queries map
type HashQueries struct {
	sync.RWMutex
	ttl time.Duration
	kv  map[uint64]int64
}

func NewHashQueries(ttl time.Duration) HashQueries {
	return HashQueries{
		ttl: ttl,
		kv:  make(map[uint64]int64),
	}
}

func (mp *HashQueries) SetTTL(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *HashQueries) Get(key uint64) (value int64, ok bool) {
	mp.RLock()
	defer mp.RUnlock()
	result, ok := mp.kv[key]
	return result, ok
}

func (mp *HashQueries) Set(key uint64, value int64) {
	mp.Lock()
	defer mp.Unlock()
	mp.kv[key] = value
	time.AfterFunc(mp.ttl, func() {
		mp.Delete(key)
	})
}

func (mp *HashQueries) Delete(key uint64) {
	mp.Lock()
	defer mp.Unlock()
	delete(mp.kv, key)
}

// latency transformer
type LatencyTransform struct {
	GenericTransformer
	hashQueries HashQueries
	mapQueries  MapQueries
}

func NewLatencyTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *LatencyTransform {
	t := &LatencyTransform{GenericTransformer: NewTransformer(config, logger, "latency", name, instance, nextWorkers)}
	t.hashQueries = NewHashQueries(time.Duration(config.Latency.QueriesTimeout) * time.Second)
	t.mapQueries = NewMapQueries(time.Duration(config.Latency.QueriesTimeout)*time.Second, nextWorkers)
	return t
}

func (t *LatencyTransform) GetTransforms() ([]Subtransform, error) {
	t.hashQueries.SetTTL(time.Duration(t.config.Latency.QueriesTimeout) * time.Second)
	t.mapQueries.SetTTL(time.Duration(t.config.Latency.QueriesTimeout) * time.Second)

	subtransforms := []Subtransform{}
	if t.config.Latency.MeasureLatency {
		subtransforms = append(subtransforms, Subtransform{name: "latency:add", processFunc: t.measureLatency})
	}
	if t.config.Latency.UnansweredQueries {
		subtransforms = append(subtransforms, Subtransform{name: "latency:timeout", processFunc: t.detectEvictedTimeout})
	}
	return subtransforms, nil
}

func (t *LatencyTransform) measureLatency(dm *dnsutils.DNSMessage) (int, error) {
	queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	if len(dm.NetworkInfo.QueryIP) > 0 && queryport > 0 && !dm.DNS.MalformedPacket {
		// compute the hash of the query
		hashData := []string{dm.NetworkInfo.QueryIP, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.ID)}

		hashfnv := fnv.New64a()
		hashfnv.Write([]byte(strings.Join(hashData, "+")))

		if dm.DNS.Type == dnsutils.DNSQuery || dm.DNS.Type == dnsutils.DNSQueryQuiet {
			t.hashQueries.Set(hashfnv.Sum64(), dm.DNSTap.Timestamp)
		} else {
			key := hashfnv.Sum64()
			value, ok := t.hashQueries.Get(key)
			if ok {
				t.hashQueries.Delete(key)
				latency := float64(dm.DNSTap.Timestamp-value) / float64(1000000000)
				dm.DNSTap.Latency = latency
			}
		}
	}
	return ReturnKeep, nil
}

func (t *LatencyTransform) detectEvictedTimeout(dm *dnsutils.DNSMessage) (int, error) {

	queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	if len(dm.NetworkInfo.QueryIP) > 0 && queryport > 0 && !dm.DNS.MalformedPacket {
		// compute the hash of the query
		hashData := []string{dm.NetworkInfo.QueryIP, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.ID)}

		hashfnv := fnv.New64a()
		hashfnv.Write([]byte(strings.Join(hashData, "+")))
		key := hashfnv.Sum64()

		if dm.DNS.Type == dnsutils.DNSQuery || dm.DNS.Type == dnsutils.DNSQueryQuiet {
			t.mapQueries.Set(key, *dm)
		} else if t.mapQueries.Exists(key) {
			t.mapQueries.Delete(key)
		}
	}
	return ReturnKeep, nil
}
