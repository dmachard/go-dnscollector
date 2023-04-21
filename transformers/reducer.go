package transformers

import (
	"container/heap"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type MapTraffic struct {
	sync.RWMutex
	ttl         time.Duration
	kv          map[uint64]*dnsutils.DnsMessage
	channels    []chan dnsutils.DnsMessage
	expiredKeys expiredKeys
}

func NewMapTraffic(ttl time.Duration, channels []chan dnsutils.DnsMessage) MapTraffic {
	return MapTraffic{
		ttl:         ttl,
		kv:          make(map[uint64]*dnsutils.DnsMessage),
		channels:    channels,
		expiredKeys: make(expiredKeys, 0),
	}
}

func (mp *MapTraffic) Exists(key uint64) (ok bool) {
	mp.RLock()
	defer mp.RUnlock()

	dm, ok := mp.kv[key]
	if ok {
		dm.DNS.Repeated += 1
	}

	return ok
}

func (mp *MapTraffic) Set(key uint64, dm *dnsutils.DnsMessage) {
	mp.Lock()
	defer mp.Unlock()

	dm.DNS.Repeated = 0
	mp.kv[key] = dm
	expTime := time.Now().Add(mp.ttl)
	heap.Push(&mp.expiredKeys, expiredKey{key, expTime})
}

func (mp *MapTraffic) Delete(key uint64) {
	delete(mp.kv, key)
}

func (mp *MapTraffic) Run() {
	flushTimer := time.NewTimer(mp.ttl)
	for range flushTimer.C {
		mp.ProcessExpiredKeys()
		flushTimer.Reset(mp.ttl)
	}
}

func (mp *MapTraffic) ProcessExpiredKeys() {
	mp.Lock()
	defer mp.Unlock()

	now := time.Now()

	for len(mp.expiredKeys) > 0 {
		expired := mp.expiredKeys[0]
		if now.Before(expired.expTime) {
			break
		}
		key := expired.key
		if dm, ok := mp.kv[key]; ok {
			for i := range mp.channels {
				mp.channels[i] <- *dm
			}
		}
		mp.Delete(key)
		heap.Pop(&mp.expiredKeys)
	}
}

type expiredKey struct {
	key     uint64
	expTime time.Time
}

type expiredKeys []expiredKey

func (ek expiredKeys) Len() int {
	return len(ek)
}

func (ek expiredKeys) Less(i, j int) bool {
	return ek[i].expTime.Before(ek[j].expTime)
}

func (ek expiredKeys) Swap(i, j int) {
	ek[i], ek[j] = ek[j], ek[i]
}

func (ek *expiredKeys) Push(x interface{}) {
	*ek = append(*ek, x.(expiredKey))
}

func (ek *expiredKeys) Pop() interface{} {
	old := *ek
	n := len(old)
	x := old[n-1]
	*ek = old[:n-1]
	return x
}

type ReducerProcessor struct {
	config           *dnsutils.ConfigTransformers
	logger           *logger.Logger
	name             string
	outChannels      []chan dnsutils.DnsMessage
	activeProcessors []func(dm *dnsutils.DnsMessage) int
	mapTraffic       MapTraffic
}

func NewReducerSubprocessor(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string, outChannels []chan dnsutils.DnsMessage) *ReducerProcessor {
	s := ReducerProcessor{
		config:      config,
		logger:      logger,
		name:        name,
		outChannels: outChannels,
	}

	s.mapTraffic = NewMapTraffic(time.Duration(config.Reducer.WatchInterval)*time.Second, outChannels)
	s.LoadActiveReducers()

	return &s
}

func (p *ReducerProcessor) LoadActiveReducers() {
	if p.config.Reducer.RepetitiveTrafficDetector {
		p.activeProcessors = append(p.activeProcessors, p.RepetitiveTrafficDetector)
		go p.mapTraffic.Run()
	}
}

func (p *ReducerProcessor) RepetitiveTrafficDetector(dm *dnsutils.DnsMessage) int {
	// compute the hash of the query
	tags := []string{dm.DnsTap.Operation, dm.NetworkInfo.QueryIp, dm.DNS.Qname, dm.DNS.Type}

	hashfnv := fnv.New64a()
	hashfnv.Write([]byte(strings.Join(tags[:], "+")))
	dmHash := hashfnv.Sum64()

	if !p.mapTraffic.Exists(dmHash) {
		p.mapTraffic.Set(dmHash, dm)
	}

	return RETURN_DROP
}

func (s *ReducerProcessor) ProcessDnsMessage(dm *dnsutils.DnsMessage) int {
	dmCopy := *dm

	if len(s.activeProcessors) == 0 {
		return RETURN_SUCCESS
	}

	if dmCopy.DNS.Repeated >= 0 {
		return RETURN_SUCCESS
	}

	var r_code int
	for _, fn := range s.activeProcessors {
		r_code = fn(&dmCopy)
		if r_code != RETURN_SUCCESS {
			return r_code
		}
	}

	return RETURN_SUCCESS
}
