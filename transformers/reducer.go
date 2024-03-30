package transformers

import (
	"container/list"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	publicsuffixlist "golang.org/x/net/publicsuffix"
)

type expiredKey struct {
	key     string
	expTime time.Time
}

type MapTraffic struct {
	sync.RWMutex
	ttl          time.Duration
	kv           *sync.Map
	channels     []chan dnsutils.DNSMessage
	expiredKeys  *list.List
	droppedCount int
	logInfo      func(msg string, v ...interface{})
	logError     func(msg string, v ...interface{})
}

func NewMapTraffic(ttl time.Duration, channels []chan dnsutils.DNSMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{})) MapTraffic {
	return MapTraffic{
		ttl:         ttl,
		kv:          &sync.Map{},
		channels:    channels,
		expiredKeys: list.New(),
		logInfo:     logInfo,
		logError:    logError,
	}
}

func (mp *MapTraffic) SetTTL(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *MapTraffic) Set(key string, dm *dnsutils.DNSMessage) {
	mp.Lock()
	defer mp.Unlock()

	if v, ok := mp.kv.Load(key); ok {
		v.(*dnsutils.DNSMessage).Reducer.Occurrences++
		v.(*dnsutils.DNSMessage).Reducer.CumulativeLength += dm.DNS.Length
		return
	}

	dm.Reducer.Occurrences = 1
	dm.Reducer.CumulativeLength = dm.DNS.Length
	mp.kv.Store(key, dm)

	expTime := time.Now().Add(mp.ttl)
	mp.expiredKeys.PushBack(expiredKey{key, expTime})

}

func (mp *MapTraffic) Run() {
	flushTimer := time.NewTimer(mp.ttl)
	for range flushTimer.C {
		if mp.droppedCount > 0 {
			mp.logError("reducer: event(s) %d dropped, output channel full", mp.droppedCount)
			mp.droppedCount = 0
		}
		mp.ProcessExpiredKeys()
		flushTimer.Reset(mp.ttl)
	}
}

func (mp *MapTraffic) ProcessExpiredKeys() {
	mp.Lock()
	defer mp.Unlock()

	now := time.Now()

	for e := mp.expiredKeys.Front(); e != nil; {
		expired := e.Value.(expiredKey)
		if now.Before(expired.expTime) {
			break
		}
		key := expired.key
		if v, ok := mp.kv.Load(key); ok {
			for i := range mp.channels {
				mp.channels[i] <- *v.(*dnsutils.DNSMessage)
			}
			mp.kv.Delete(key)
		}

		next := e.Next()
		mp.expiredKeys.Remove(e)
		e = next
	}
}

type ReducerProcessor struct {
	config            *pkgconfig.ConfigTransformers
	logger            *logger.Logger
	outChannels       []chan dnsutils.DNSMessage
	activeProcessors  []func(dm *dnsutils.DNSMessage) int
	mapTraffic        MapTraffic
	LogInfo, LogError func(msg string, v ...interface{})
	strBuilder        strings.Builder
}

func NewReducerTransform(
	config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage) *ReducerProcessor {
	s := ReducerProcessor{config: config, logger: logger, outChannels: outChannels}

	s.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - reducer - ", name, instance)
		logger.Info(log+msg, v...)
	}

	s.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("transformer - [%s] conn #%d - reducer - ", name, instance)
		logger.Error(log+msg, v...)
	}

	s.mapTraffic = NewMapTraffic(time.Duration(config.Reducer.WatchInterval)*time.Second, outChannels, s.LogInfo, s.LogError)

	return &s
}

func (p *ReducerProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config
	p.mapTraffic.SetTTL(time.Duration(config.Reducer.WatchInterval) * time.Second)

	p.LoadActiveReducers()
}

func (p *ReducerProcessor) LoadActiveReducers() {
	// clean the slice
	p.activeProcessors = p.activeProcessors[:0]

	if p.config.Reducer.RepetitiveTrafficDetector {
		p.activeProcessors = append(p.activeProcessors, p.RepetitiveTrafficDetector)
		go p.mapTraffic.Run()
	}
}

func (p *ReducerProcessor) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.Reducer == nil {
		dm.Reducer = &dnsutils.TransformReducer{
			Occurrences:      0,
			CumulativeLength: 0,
		}
	}
}

func (p *ReducerProcessor) RepetitiveTrafficDetector(dm *dnsutils.DNSMessage) int {
	p.strBuilder.Reset()
	p.strBuilder.WriteString(dm.DNSTap.Identity)
	p.strBuilder.WriteString(dm.DNSTap.Operation)
	p.strBuilder.WriteString(dm.NetworkInfo.QueryIP)
	if p.config.Reducer.QnamePlusOne {
		qname := strings.ToLower(dm.DNS.Qname)
		qname = strings.TrimSuffix(qname, ".")
		if etld, err := publicsuffixlist.EffectiveTLDPlusOne(qname); err == nil {
			dm.DNS.Qname = etld
		}
	}
	p.strBuilder.WriteString(dm.DNS.Qname)
	p.strBuilder.WriteString(dm.DNS.Qtype)
	dmTag := p.strBuilder.String()

	p.mapTraffic.Set(dmTag, dm)

	return ReturnDrop
}

func (p *ReducerProcessor) ProcessDNSMessage(dm *dnsutils.DNSMessage) int {
	dmCopy := *dm

	if len(p.activeProcessors) == 0 {
		return ReturnSuccess
	}

	var rCode int
	for _, fn := range p.activeProcessors {
		rCode = fn(&dmCopy)
		if rCode != ReturnSuccess {
			return rCode
		}
	}

	return ReturnSuccess
}
