package pkgutils

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type Worker interface {
	AddDefaultRoute(wrk Worker)
	AddDroppedRoute(wrk Worker)
	SetLoggers(loggers []Worker)
	GetName() string
	Stop()
	StartCollect()
	GetInputChannel() chan dnsutils.DNSMessage
	ReadConfig()
	ReloadConfig(config *pkgconfig.Config)
}

type GenericWorker struct {
	doneRun, stopRun, stopProcess, doneProcess, doneMonitor, stopMonitor chan bool
	config                                                               *pkgconfig.Config
	configChan                                                           chan *pkgconfig.Config
	logger                                                               *logger.Logger
	name, descr                                                          string
	droppedRoutes, defaultRoutes                                         []Worker
	droppedWorker                                                        chan string
	droppedWorkerCount                                                   map[string]int
	dnsMessageIn, dnsMessageOut                                          chan dnsutils.DNSMessage
}

func NewGenericWorker(config *pkgconfig.Config, logger *logger.Logger, name string, descr string, bufferSize int, monitor bool) *GenericWorker {
	logger.Info(PrefixLogWorker+"[%s] %s - enabled", name, descr)
	w := &GenericWorker{
		config:             config,
		configChan:         make(chan *pkgconfig.Config),
		logger:             logger,
		name:               name,
		descr:              descr,
		doneRun:            make(chan bool),
		doneMonitor:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		stopMonitor:        make(chan bool),
		stopProcess:        make(chan bool),
		droppedWorker:      make(chan string),
		droppedWorkerCount: map[string]int{},
		dnsMessageIn:       make(chan dnsutils.DNSMessage, bufferSize),
		dnsMessageOut:      make(chan dnsutils.DNSMessage, bufferSize),
	}
	if monitor {
		go w.Monitor()
	}
	return w
}

func (w *GenericWorker) GetName() string { return w.name }

func (w *GenericWorker) GetConfig() *pkgconfig.Config { return w.config }

func (w *GenericWorker) SetConfig(config *pkgconfig.Config) { w.config = config }

func (w *GenericWorker) ReadConfig() {}

func (w *GenericWorker) NewConfig() chan *pkgconfig.Config { return w.configChan }

func (w *GenericWorker) GetLogger() *logger.Logger { return w.logger }

func (w *GenericWorker) GetDroppedRoutes() []Worker { return w.droppedRoutes }

func (w *GenericWorker) GetDefaultRoutes() []Worker { return w.defaultRoutes }

func (w *GenericWorker) GetInputChannel() chan dnsutils.DNSMessage { return w.dnsMessageIn }

func (w *GenericWorker) GetInputChannelAsList() []chan dnsutils.DNSMessage {
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, w.GetInputChannel())
	return listChannel
}

func (w *GenericWorker) GetOutputChannel() chan dnsutils.DNSMessage { return w.dnsMessageOut }

func (w *GenericWorker) GetOutputChannelAsList() []chan dnsutils.DNSMessage {
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, w.GetOutputChannel())
	return listChannel
}

func (w *GenericWorker) AddDroppedRoute(wrk Worker) {
	w.droppedRoutes = append(w.droppedRoutes, wrk)
}

func (w *GenericWorker) AddDefaultRoute(wrk Worker) {
	w.defaultRoutes = append(w.defaultRoutes, wrk)
}

func (w *GenericWorker) SetDefaultRoutes(workers []Worker) {
	w.defaultRoutes = workers
}

func (w *GenericWorker) SetDefaultDropped(workers []Worker) {
	w.droppedRoutes = workers
}

func (w *GenericWorker) SetLoggers(loggers []Worker) { w.defaultRoutes = loggers }

func (w *GenericWorker) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return GetRoutes(w.defaultRoutes)
}

func (w *GenericWorker) ReloadConfig(config *pkgconfig.Config) {
	w.LogInfo("reload configuration...")
	w.configChan <- config
}

func (w *GenericWorker) LogInfo(msg string, v ...interface{}) {
	w.logger.Info(PrefixLogWorker+"["+w.name+"] "+w.descr+" - "+msg, v...)
}

func (w *GenericWorker) LogError(msg string, v ...interface{}) {
	w.logger.Error(PrefixLogWorker+"["+w.name+"] "+w.descr+" - "+msg, v...)
}

func (w *GenericWorker) LogFatal(v ...interface{}) {
	w.logger.Fatal(v...)
}

func (w *GenericWorker) OnStop() chan bool {
	return w.stopRun
}

func (w *GenericWorker) OnLoggerStopped() chan bool {
	return w.stopProcess
}

func (w *GenericWorker) StopLogger() {
	w.stopProcess <- true
	<-w.doneProcess
}

func (w *GenericWorker) CollectDone() {
	w.LogInfo("collection terminated")
	w.doneRun <- true
}

func (w *GenericWorker) LoggingDone() {
	w.LogInfo("logging terminated")
	w.doneProcess <- true
}

func (w *GenericWorker) Stop() {
	w.LogInfo("stopping monitor...")
	w.stopMonitor <- true
	<-w.doneMonitor

	w.LogInfo("stopping collect...")
	w.stopRun <- true
	<-w.doneRun
}

func (w *GenericWorker) Monitor() {
	defer func() {
		w.LogInfo("monitor terminated")
		w.doneMonitor <- true
	}()

	w.LogInfo("start to monitor")
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
	for {
		select {
		case loggerName := <-w.droppedWorker:
			if _, ok := w.droppedWorkerCount[loggerName]; !ok {
				w.droppedWorkerCount[loggerName] = 1
			} else {
				w.droppedWorkerCount[loggerName]++
			}

		case <-w.stopMonitor:
			close(w.droppedWorker)
			bufferFull.Stop()
			return

		case <-bufferFull.C:
			for v, k := range w.droppedWorkerCount {
				if k > 0 {
					w.LogError("worker[%s] buffer is full, %d dnsmessage(s) dropped", v, k)
					w.droppedWorkerCount[v] = 0
				}
			}

			bufferFull.Reset(watchInterval)
		}
	}
}

func (w *GenericWorker) WorkerIsBusy(name string) {
	w.droppedWorker <- name
}

func (w *GenericWorker) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()
}

func (w *GenericWorker) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()
}

func (w *GenericWorker) SendTo(routes []chan dnsutils.DNSMessage, routesName []string, dm dnsutils.DNSMessage) {
	for i := range routes {
		select {
		case routes[i] <- dm:
		default:
			w.WorkerIsBusy(routesName[i])
		}
	}
}

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

func GetName(name string) string {
	return "[" + name + "] - "
}

func GetWorkerForTest(bufferSize int) *GenericWorker {
	return NewGenericWorker(pkgconfig.GetDefaultConfig(), logger.New(false), "testonly", "", bufferSize, WorkerMonitorDisabled)
}
