package transformers

import (
	"container/list"
	"fmt"
	"reflect"
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

type ReducerTransform struct {
	GenericTransformer
	mapTraffic MapTraffic
	strBuilder strings.Builder
}

func NewReducerTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *ReducerTransform {
	t := &ReducerTransform{GenericTransformer: NewTransformer(config, logger, "reducer", name, instance, nextWorkers)}
	t.mapTraffic = NewMapTraffic(time.Duration(config.Reducer.WatchInterval)*time.Second, nextWorkers, t.LogInfo, t.LogError)
	return t
}

func (t *ReducerTransform) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	t.GenericTransformer.ReloadConfig(config)
	t.mapTraffic.SetTTL(time.Duration(config.Reducer.WatchInterval) * time.Second)
	t.GetTransforms()
}

func (t *ReducerTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Reducer.RepetitiveTrafficDetector {
		subtransforms = append(subtransforms, Subtransform{name: "reducer", processFunc: t.repetitiveTrafficDetector})
		go t.mapTraffic.Run()
	}
	return subtransforms, nil
}

func (t *ReducerTransform) repetitiveTrafficDetector(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Reducer == nil {
		dm.Reducer = &dnsutils.TransformReducer{}
	}

	t.strBuilder.Reset()

	// update qname ?
	if t.config.Reducer.QnamePlusOne {
		qname := strings.ToLower(dm.DNS.Qname)
		qname = strings.TrimSuffix(qname, ".")
		if etld, err := publicsuffixlist.EffectiveTLDPlusOne(qname); err == nil {
			dm.DNS.Qname = etld
		}
	}

	dmValue := reflect.ValueOf(dm).Elem() // Get the struct value of the DNSMessage
	for _, field := range t.config.Reducer.UniqueFields {
		if value, found := dnsutils.GetFieldByJSONTag(dmValue, field); found {
			// Check if the field's kind is either int or string
			switch value.Kind() {
			case reflect.Int, reflect.String:
				t.strBuilder.WriteString(fmt.Sprintf("%v", value.Interface())) // Append field value
			default:
				// Skip unsupported types
				continue
			}
		}
	}

	dmTag := t.strBuilder.String()

	dmCopy := *dm
	t.mapTraffic.Set(dmTag, &dmCopy)

	return ReturnDrop, nil
}
