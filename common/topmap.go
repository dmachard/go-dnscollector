package common

import (
	"sort"
	"sync"
)

type MapItem struct {
	Name string `json:"key"`
	Hit  int    `json:"hit"`
}

// sort interface
type ByHit []MapItem

func (a ByHit) Len() int           { return len(a) }
func (a ByHit) Less(i, j int) bool { return a[i].Hit < a[j].Hit }
func (a ByHit) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type TopMap struct {
	minvalue int
	minindex string
	maxitems int
	items    map[string]int
	sync.RWMutex
}

func NewTopMap(maxitems int) *TopMap {
	q := &TopMap{
		minvalue: 0,
		minindex: "",
		maxitems: maxitems,
		items:    make(map[string]int),
	}
	return q
}

func (q *TopMap) FindMin() {
	var minval int
	var minkey string
	for k, v := range q.items {
		if minval == 0 {
			minval = v
			minkey = k
		} else {
			if v <= minval {
				minval = v
				minkey = k
			}
		}
	}
	q.minvalue = minval
	q.minindex = minkey
}

func (q *TopMap) Record(name string, hit int) {
	q.Lock()
	defer q.Unlock()
	if len(q.items) >= q.maxitems {
		if hit > q.minvalue {
			if _, ok := q.items[name]; !ok {
				delete(q.items, q.minindex)
			}
			q.items[name] = hit
		}
	} else {
		q.items[name] = hit
	}
	q.FindMin()
}

func (q *TopMap) Get() []MapItem {
	q.RLock()
	defer q.RUnlock()

	retMap := []MapItem{}
	for k, v := range q.items {
		retMap = append(retMap, MapItem{k, v})
	}

	sort.Sort(sort.Reverse(ByHit(retMap)))
	return retMap
}
