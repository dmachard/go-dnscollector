package transformers

import (
	"fmt"
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

// latency processor
type LatencyProcessor struct {
	config      *pkgconfig.ConfigTransformers
	logger      *logger.Logger
	name        string
	instance    int
	hashQueries HashQueries
	mapQueries  MapQueries
	outChannels []chan dnsutils.DNSMessage
	LogInfo     func(msg string, v ...interface{})
	LogError    func(msg string, v ...interface{})
}

func NewLatencyTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage) *LatencyProcessor {
	s := LatencyProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		instance:    instance,
		outChannels: outChannels,
	}

	s.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - latency - ", name, instance)
		logger.Info(log+msg, v...)
	}

	s.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - latency - ", name, instance)
		logger.Error(log+msg, v...)
	}

	s.hashQueries = NewHashQueries(time.Duration(config.Latency.QueriesTimeout) * time.Second)
	s.mapQueries = NewMapQueries(time.Duration(config.Latency.QueriesTimeout)*time.Second, outChannels)

	return &s
}

func (s *LatencyProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	s.config = config

	s.hashQueries.SetTTL(time.Duration(config.Latency.QueriesTimeout) * time.Second)
	s.mapQueries.SetTTL(time.Duration(config.Latency.QueriesTimeout) * time.Second)
}

func (s *LatencyProcessor) MeasureLatency(dm *dnsutils.DNSMessage) {
	queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	if len(dm.NetworkInfo.QueryIP) > 0 && queryport > 0 && !dm.DNS.MalformedPacket {
		// compute the hash of the query
		hashData := []string{dm.NetworkInfo.QueryIP, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.ID)}

		hashfnv := fnv.New64a()
		hashfnv.Write([]byte(strings.Join(hashData, "+")))

		if dm.DNS.Type == dnsutils.DNSQuery || dm.DNS.Type == dnsutils.DNSQueryQuiet {
			s.hashQueries.Set(hashfnv.Sum64(), dm.DNSTap.Timestamp)
		} else {
			key := hashfnv.Sum64()
			value, ok := s.hashQueries.Get(key)
			if ok {
				s.hashQueries.Delete(key)
				latency := float64(dm.DNSTap.Timestamp-value) / float64(1000000000)
				dm.DNSTap.Latency = latency
			}
		}
	}
}

func (s *LatencyProcessor) DetectEvictedTimeout(dm *dnsutils.DNSMessage) {

	queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	if len(dm.NetworkInfo.QueryIP) > 0 && queryport > 0 && !dm.DNS.MalformedPacket {
		// compute the hash of the query
		hashData := []string{dm.NetworkInfo.QueryIP, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.ID)}

		hashfnv := fnv.New64a()
		hashfnv.Write([]byte(strings.Join(hashData, "+")))
		key := hashfnv.Sum64()

		if dm.DNS.Type == dnsutils.DNSQuery || dm.DNS.Type == dnsutils.DNSQueryQuiet {
			s.mapQueries.Set(key, *dm)
		} else if s.mapQueries.Exists(key) {
			s.mapQueries.Delete(key)
		}
	}
}
