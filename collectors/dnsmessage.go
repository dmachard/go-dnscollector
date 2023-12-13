package collectors

import (
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type DNSMessage struct {
	doneRun      chan bool
	doneMonitor  chan bool
	stopRun      chan bool
	stopMonitor  chan bool
	loggers      []dnsutils.Worker
	config       *pkgconfig.Config
	configChan   chan *pkgconfig.Config
	inputChan    chan dnsutils.DNSMessage
	logger       *logger.Logger
	name         string
	droppedCount map[string]int
	dropped      chan string
}

func NewDNSMessage(loggers []dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *DNSMessage {
	logger.Info("[%s] collector=dnsmessage - enabled", name)
	s := &DNSMessage{
		doneRun:      make(chan bool),
		doneMonitor:  make(chan bool),
		stopRun:      make(chan bool),
		stopMonitor:  make(chan bool),
		config:       config,
		configChan:   make(chan *pkgconfig.Config),
		inputChan:    make(chan dnsutils.DNSMessage, config.Collectors.DNSMessage.ChannelBufferSize),
		loggers:      loggers,
		logger:       logger,
		name:         name,
		dropped:      make(chan string),
		droppedCount: map[string]int{},
	}
	s.ReadConfig()
	return s
}

func (c *DNSMessage) GetName() string { return c.name }

func (c *DNSMessage) AddRoute(wrk dnsutils.Worker) {
	c.loggers = append(c.loggers, wrk)
}

func (c *DNSMessage) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *DNSMessage) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	channels := []chan dnsutils.DNSMessage{}
	names := []string{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
		names = append(names, p.GetName())
	}
	return channels, names
}

func (c *DNSMessage) ReadConfig() {}

func (c *DNSMessage) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration...")
	c.configChan <- config
}

func (c *DNSMessage) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] collector=dnsmessage - "+msg, v...)
}

func (c *DNSMessage) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+" collector=dnsmessage - "+msg, v...)
}

func (c *DNSMessage) Channel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *DNSMessage) Stop() {
	// stop monitor goroutine
	c.LogInfo("stopping monitor...")
	c.stopMonitor <- true
	<-c.doneMonitor

	// read done channel and block until run is terminated
	c.LogInfo("stopping run...")
	c.stopRun <- true
	<-c.doneRun
}

func (c *DNSMessage) MonitorCollector() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
MONITOR_LOOP:
	for {
		select {
		case <-c.stopMonitor:
			close(c.dropped)
			bufferFull.Stop()
			c.doneMonitor <- true
			break MONITOR_LOOP

		case loggerName := <-c.dropped:
			if _, ok := c.droppedCount[loggerName]; !ok {
				c.droppedCount[loggerName] = 1
			} else {
				c.droppedCount[loggerName]++
			}

		case <-bufferFull.C:
			for v, k := range c.droppedCount {
				if k > 0 {
					c.LogError("logger[%s] buffer is full, %d packet(s) dropped", v, k)
					c.droppedCount[v] = 0
				}
			}
			bufferFull.Reset(watchInterval)
		}
	}
	c.LogInfo("monitor terminated")
}

func (c *DNSMessage) Run() {
	c.LogInfo("starting collector...")
	var err error

	// prepare next channels
	loggersChannel, loggersName := c.Loggers()

	// prepare transforms
	subprocessors := transformers.NewTransforms(&c.config.IngoingTransformers, c.logger, c.name, loggersChannel, 0)

	// start goroutine to count dropped messsages
	go c.MonitorCollector()

RUN_LOOP:
	for {
		select {
		case <-c.stopRun:
			c.doneRun <- true
			break RUN_LOOP

		case cfg := <-c.configChan:

			// save the new config
			c.config = cfg
			c.ReadConfig()

		case dm, opened := <-c.inputChan:
			if !opened {
				c.LogInfo("channel closed, exit")
				return
			}

			// matching enabled, filtering DNS messages ?
			matched := true
			matchedInclude := false
			matchedGreaterThan := false

			if len(c.config.Collectors.DNSMessage.Matching.Include) > 0 {
				err, matchedInclude = dm.Matching(c.config.Collectors.DNSMessage.Matching.Include,
					dnsutils.MatchingModeInclude)
				if err != nil {
					c.LogError(err.Error())
				}
				if matched && matchedInclude {
					matched = true
				} else {
					matched = false
				}
			}
			if len(c.config.Collectors.DNSMessage.Matching.GreaterThan) > 0 {
				err, matchedGreaterThan = dm.Matching(c.config.Collectors.DNSMessage.Matching.GreaterThan,
					dnsutils.MatchingModeGreaterThan)
				if err != nil {
					c.LogError(err.Error())
				}

				if matched && matchedGreaterThan {
					matched = true
				} else {
					matched = false
				}
			}

			// apply tranforms on matched packets only
			// init dns message with additionnals parts if necessary
			if matched {
				subprocessors.InitDNSMessageFormat(&dm)
				if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
					continue
				}
			}

			// drop unmatched packet ?
			if c.config.Collectors.DNSMessage.Policy == "drop-unmatched" && !matched {
				continue
			}

			// send to next
			for i := range loggersChannel {
				select {
				case loggersChannel[i] <- dm: // Successful send to logger channel
				default:
					c.dropped <- loggersName[i]
				}
			}

		}

	}
	c.LogInfo("run terminated")
}