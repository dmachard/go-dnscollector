package loggers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

type DevNull struct {
	stopProcess, doneProcess chan bool
	stopRun, doneRun         chan bool
	inputChan, outputChan    chan dnsutils.DNSMessage
	config                   *pkgconfig.Config
	configChan               chan *pkgconfig.Config
	logger                   *logger.Logger
	name                     string
	RoutingHandler           pkgutils.RoutingHandler
}

func NewDevNull(config *pkgconfig.Config, console *logger.Logger, name string) *DevNull {
	console.Info(pkgutils.PrefixLogLogger+"[%s] devnull - enabled", name)
	so := &DevNull{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.Stdout.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.Stdout.ChannelBufferSize),
		logger:         console,
		config:         config,
		configChan:     make(chan *pkgconfig.Config),
		name:           name,
		RoutingHandler: pkgutils.NewRoutingHandler(config, console, name),
	}
	return so
}

func (so *DevNull) GetName() string { return so.name }

func (so *DevNull) AddDroppedRoute(wrk pkgutils.Worker) {
	so.RoutingHandler.AddDroppedRoute(wrk)
}

func (so *DevNull) AddDefaultRoute(wrk pkgutils.Worker) {
	so.RoutingHandler.AddDefaultRoute(wrk)
}

func (so *DevNull) SetLoggers(loggers []pkgutils.Worker) {}

func (so *DevNull) ReadConfig() {}

func (so *DevNull) ReloadConfig(config *pkgconfig.Config) {
	so.LogInfo("reload configuration!")
	so.configChan <- config
}

func (so *DevNull) LogInfo(msg string, v ...interface{}) {
	so.logger.Info(pkgutils.PrefixLogLogger+"["+so.name+"] devnull - "+msg, v...)
}

func (so *DevNull) LogError(msg string, v ...interface{}) {
	so.logger.Error(pkgutils.PrefixLogLogger+"["+so.name+"] devnull - "+msg, v...)
}

func (so *DevNull) GetInputChannel() chan dnsutils.DNSMessage {
	return so.inputChan
}

func (so *DevNull) Stop() {
	so.LogInfo("stopping logger...")
	so.RoutingHandler.Stop()

	so.LogInfo("stopping to run...")
	so.stopRun <- true
	<-so.doneRun

	so.LogInfo("stopping to process...")
	so.stopProcess <- true
	<-so.doneProcess
}

func (so *DevNull) Run() {
	so.LogInfo("running in background...")

	// goroutine to process transformed dns messages
	go so.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-so.stopRun:
			so.doneRun <- true
			break RUN_LOOP

		case _, opened := <-so.inputChan:
			if !opened {
				so.LogInfo("run: input channel closed!")
				return
			}

			// send to output channel
			//	so.outputChan <- dm
		}
	}
	so.LogInfo("run terminated")
}

func (so *DevNull) Process() {
	so.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-so.stopProcess:
			so.doneProcess <- true
			break PROCESS_LOOP

		case _, opened := <-so.outputChan:
			if !opened {
				so.LogInfo("process: output channel closed!")
				return
			}

		}
	}
	so.LogInfo("processing terminated")
}
