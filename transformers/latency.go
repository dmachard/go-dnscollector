package transformers

import (
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

// queries map
type MapQueries struct {
	sync.RWMutex
	ttl      time.Duration
	kv       map[uint64]dnsutils.DnsMessage
	channels []chan dnsutils.DnsMessage
}

func NewMapQueries(ttl time.Duration, channels []chan dnsutils.DnsMessage) MapQueries {
	return MapQueries{
		ttl:      ttl,
		kv:       make(map[uint64]dnsutils.DnsMessage),
		channels: channels,
	}
}

func (mp *MapQueries) Exists(key uint64) (ok bool) {
	mp.RLock()
	defer mp.RUnlock()
	_, ok = mp.kv[key]
	return ok
}

func (mp *MapQueries) Set(key uint64, dm dnsutils.DnsMessage) {
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
	kv  map[uint64]float64
}

func NewHashQueries(ttl time.Duration) HashQueries {
	return HashQueries{
		ttl: ttl,
		kv:  make(map[uint64]float64),
	}
}

func (mp *HashQueries) Get(key uint64) (value float64, ok bool) {
	mp.RLock()
	defer mp.RUnlock()
	result, ok := mp.kv[key]
	return result, ok
}

func (mp *HashQueries) Set(key uint64, value float64) {
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

// latency processor
type LatencyProcessor struct {
	config      *dnsutils.ConfigTransformers
	logger      *logger.Logger
	name        string
	hashQueries HashQueries
	mapQueries  MapQueries
	outChannels []chan dnsutils.DnsMessage
}

func NewLatencySubprocessor(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string, outChannels []chan dnsutils.DnsMessage) *LatencyProcessor {
	s := LatencyProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		outChannels: outChannels,
	}

	s.hashQueries = NewHashQueries(time.Duration(config.Latency.QueriesTimeout) * time.Second)
	s.mapQueries = NewMapQueries(time.Duration(config.Latency.QueriesTimeout)*time.Second, outChannels)

	return &s
}

func (s *LatencyProcessor) MeasureLatency(dm *dnsutils.DnsMessage) {
	queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	if len(dm.NetworkInfo.QueryIp) > 0 && queryport > 0 && !dm.DNS.MalformedPacket {
		// compute the hash of the query
		hash_data := []string{dm.NetworkInfo.QueryIp, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.Id)}

		hashfnv := fnv.New64a()
		hashfnv.Write([]byte(strings.Join(hash_data[:], "+")))

		if dm.DNS.Type == dnsutils.DnsQuery {
			s.hashQueries.Set(hashfnv.Sum64(), dm.DnsTap.Timestamp)
		} else {
			key := hashfnv.Sum64()
			value, ok := s.hashQueries.Get(key)
			if ok {
				s.hashQueries.Delete(key)
				dm.DnsTap.Latency = dm.DnsTap.Timestamp - value
			}
		}
	}
}

func (s *LatencyProcessor) DetectEvictedTimeout(dm *dnsutils.DnsMessage) {

	queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	if len(dm.NetworkInfo.QueryIp) > 0 && queryport > 0 && !dm.DNS.MalformedPacket {
		// compute the hash of the query
		hash_data := []string{dm.NetworkInfo.QueryIp, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.Id)}

		hashfnv := fnv.New64a()
		hashfnv.Write([]byte(strings.Join(hash_data[:], "+")))
		key := hashfnv.Sum64()

		if dm.DNS.Type == dnsutils.DnsQuery {
			s.mapQueries.Set(key, *dm)
		} else {
			if s.mapQueries.Exists(key) {
				s.mapQueries.Delete(key)
			}
		}
	}
}
