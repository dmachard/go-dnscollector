package pkgutils

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func GetRoutes(routes []Worker) ([]chan dnsutils.DNSMessage, []string) {
	channels := []chan dnsutils.DNSMessage{}
	names := []string{}
	for _, p := range routes {
		if c := p.GetInputChannel(); c != nil {
			channels = append(channels, c)
			names = append(names, p.GetName())
		} else {
			panic("default routing to stanza=[" + p.GetName() + "] not supported")
		}
	}
	return channels, names
}

type RoutingHandler struct {
	name          string
	logger        *logger.Logger
	config        *pkgconfig.Config
	stopRun       chan bool
	doneRun       chan bool
	droppedCount  map[string]int
	dropped       chan string
	droppedRoutes []Worker
	defaultRoutes []Worker
}

func NewRoutingHandler(config *pkgconfig.Config, console *logger.Logger, name string) RoutingHandler {
	console.Info("routing - [%s] - initialization...", name)
	rh := RoutingHandler{
		name:         name,
		logger:       console,
		config:       config,
		stopRun:      make(chan bool),
		doneRun:      make(chan bool),
		dropped:      make(chan string),
		droppedCount: map[string]int{},
	}
	go rh.Run()
	return rh
}

func (rh *RoutingHandler) LogInfo(msg string, v ...interface{}) {
	rh.logger.Info(PrefixLogRouting+"["+rh.name+"] - "+msg, v...)
}

func (rh *RoutingHandler) LogError(msg string, v ...interface{}) {
	rh.logger.Error(PrefixLogRouting+"["+rh.name+"] - "+msg, v...)
}

func (rh *RoutingHandler) LogFatal(msg string) {
	rh.logger.Error(PrefixLogRouting + "[" + rh.name + "] - " + msg)
}

func (rh *RoutingHandler) AddDroppedRoute(wrk Worker) {
	rh.droppedRoutes = append(rh.droppedRoutes, wrk)
}

func (rh *RoutingHandler) AddDefaultRoute(wrk Worker) {
	rh.defaultRoutes = append(rh.defaultRoutes, wrk)
}

func (rh *RoutingHandler) SetDefaultRoutes(workers []Worker) {
	rh.defaultRoutes = workers
}

func (rh *RoutingHandler) GetDefaultRoutes() ([]chan dnsutils.DNSMessage, []string) {
	return GetRoutes(rh.defaultRoutes)
}

func (rh *RoutingHandler) GetDroppedRoutes() ([]chan dnsutils.DNSMessage, []string) {
	return GetRoutes(rh.droppedRoutes)
}

func (rh *RoutingHandler) Stop() {
	rh.LogInfo("stopping to run...")
	rh.stopRun <- true
	<-rh.doneRun
}

func (rh *RoutingHandler) Run() {
	rh.LogInfo("running in background...")
	nextBufferInterval := 10 * time.Second
	nextBufferFull := time.NewTimer(nextBufferInterval)

RUN_LOOP:
	for {
		select {
		case <-rh.stopRun:
			nextBufferFull.Stop()
			rh.doneRun <- true
			break RUN_LOOP
		case stanzaName := <-rh.dropped:
			if _, ok := rh.droppedCount[stanzaName]; !ok {
				rh.droppedCount[stanzaName] = 1
			} else {
				rh.droppedCount[stanzaName]++
			}
		case <-nextBufferFull.C:
			for v, k := range rh.droppedCount {
				if k > 0 {
					rh.LogError("stanza=%s buffer is full, %d packet(s) dropped", v, k)
					rh.droppedCount[v] = 0
				}
			}
			nextBufferFull.Reset(nextBufferInterval)
		}
	}

	rh.LogInfo("run terminated")
}

func (rh *RoutingHandler) SendTo(routes []chan dnsutils.DNSMessage, routesName []string, dm dnsutils.DNSMessage) {
	for i := range routes {
		select {
		case routes[i] <- dm:
		default:
			rh.dropped <- routesName[i]
		}
	}
}
