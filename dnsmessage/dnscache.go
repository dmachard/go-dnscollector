package dnsmessage

import (
	"sync"
	"time"
)

type MapTTL struct {
	sync.RWMutex
	ttl time.Duration
	//	kv  map[string]interface{}
	kv map[uint64]float64
}

func NewCacheDns(ttl time.Duration) *MapTTL {
	return &MapTTL{
		ttl: ttl,
		//kv:  map[string]interface{}{},
		kv: make(map[uint64]float64),
	}
}

func (mp *MapTTL) Get(key uint64) (value float64, ok bool) { //interface{} {
	mp.RLock()
	defer mp.RUnlock()
	result, ok := mp.kv[key]
	return result, ok
}

func (mp *MapTTL) Set(key uint64, value float64) { //interface{}) {
	mp.Lock()
	defer mp.Unlock()
	mp.kv[key] = value
	time.AfterFunc(mp.ttl, func() {
		mp.Delete(key)
	})
}

func (mp *MapTTL) Delete(key uint64) {
	mp.Lock()
	defer mp.Unlock()
	delete(mp.kv, key)
}
