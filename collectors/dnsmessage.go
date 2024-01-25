package collectors

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

func isFileSource(matchSource string) bool {
	return strings.HasPrefix(matchSource, "file://")
}

func isURLSource(matchSource string) bool {
	return strings.HasPrefix(matchSource, "http://") || strings.HasPrefix(matchSource, "https://")
}

type MatchSource struct {
	regexList  []*regexp.Regexp
	stringList []string
}

type DNSMessage struct {
	doneRun     chan bool
	doneMonitor chan bool
	stopRun     chan bool
	stopMonitor chan bool
	config      *pkgconfig.Config
	configChan  chan *pkgconfig.Config
	inputChan   chan dnsutils.DNSMessage
	logger      *logger.Logger
	name        string
	//	RoutingHandler pkgutils.RoutingHandler
	droppedRoutes []pkgutils.Worker
	defaultRoutes []pkgutils.Worker
	dropped       chan string
	droppedCount  map[string]int
}

func NewDNSMessage(loggers []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *DNSMessage {
	logger.Info("[%s] collector=dnsmessage - enabled", name)
	s := &DNSMessage{
		doneRun:     make(chan bool),
		doneMonitor: make(chan bool),
		stopRun:     make(chan bool),
		stopMonitor: make(chan bool),
		config:      config,
		configChan:  make(chan *pkgconfig.Config),
		inputChan:   make(chan dnsutils.DNSMessage, config.Collectors.DNSMessage.ChannelBufferSize),
		logger:      logger,
		name:        name,
		//RoutingHandler: pkgutils.NewRoutingHandler(config, logger, name),
		dropped:      make(chan string),
		droppedCount: map[string]int{},
	}
	s.ReadConfig()
	return s
}

func (c *DNSMessage) GetName() string { return c.name }

func (c *DNSMessage) AddDroppedRoute(wrk pkgutils.Worker) {
	//c.RoutingHandler.AddDroppedRoute(wrk)
	c.droppedRoutes = append(c.droppedRoutes, wrk)
}

func (c *DNSMessage) AddDefaultRoute(wrk pkgutils.Worker) {
	//c.RoutingHandler.AddDefaultRoute(wrk)
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

// deprecated function
func (c *DNSMessage) SetLoggers(loggers []pkgutils.Worker) {}

// deprecated function
func (c *DNSMessage) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return nil, nil
}

func (c *DNSMessage) ReadConfigMatching(value interface{}) {
	reflectedValue := reflect.ValueOf(value)
	if reflectedValue.Kind() == reflect.Map {
		keys := reflectedValue.MapKeys()
		matchSrc := ""
		srcKind := dnsutils.MatchingKindString
		for _, k := range keys {
			v := reflectedValue.MapIndex(k)
			if k.Interface().(string) == "match-source" {
				matchSrc = v.Interface().(string)
			}
			if k.Interface().(string) == "source-kind" {
				srcKind = v.Interface().(string)
			}
		}
		if len(matchSrc) > 0 {
			sourceData, err := c.LoadData(matchSrc, srcKind)
			if err != nil {
				c.logger.Fatal(err)
			}
			if len(sourceData.regexList) > 0 {
				value.(map[interface{}]interface{})[srcKind] = sourceData.regexList
			}
			if len(sourceData.stringList) > 0 {
				value.(map[interface{}]interface{})[srcKind] = sourceData.stringList
			}
		}
	}
}

func (c *DNSMessage) GetInputChannel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *DNSMessage) ReadConfig() {
	// load external file for include
	if len(c.config.Collectors.DNSMessage.Matching.Include) > 0 {
		for _, value := range c.config.Collectors.DNSMessage.Matching.Include {
			c.ReadConfigMatching(value)
		}
	}
	// load external file for exclude
	if len(c.config.Collectors.DNSMessage.Matching.Exclude) > 0 {
		for _, value := range c.config.Collectors.DNSMessage.Matching.Exclude {
			c.ReadConfigMatching(value)
		}
	}
}

func (c *DNSMessage) LoadData(matchSource string, srcKind string) (MatchSource, error) {
	if isFileSource(matchSource) {
		dataSource, err := c.LoadFromFile(matchSource, srcKind)
		if err != nil {
			c.logger.Fatal(err)
		}
		return dataSource, nil
	} else if isURLSource(matchSource) {
		dataSource, err := c.LoadFromURL(matchSource, srcKind)
		if err != nil {
			c.logger.Fatal(err)
		}
		return dataSource, nil
	}
	return MatchSource{}, fmt.Errorf("match source not supported %s", matchSource)
}

func (c *DNSMessage) LoadFromURL(matchSource string, srcKind string) (MatchSource, error) {
	c.LogInfo("loading matching source from url=%s", matchSource)
	resp, err := http.Get(matchSource)
	if err != nil {
		return MatchSource{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MatchSource{}, fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	matchSources := MatchSource{}
	scanner := bufio.NewScanner(resp.Body)

	switch srcKind {
	case dnsutils.MatchingKindRegexp:
		for scanner.Scan() {
			matchSources.regexList = append(matchSources.regexList, regexp.MustCompile(scanner.Text()))
		}
		c.LogInfo("remote source loaded with %d entries kind=%s", len(matchSources.regexList), srcKind)
	case dnsutils.MatchingKindString:
		for scanner.Scan() {
			matchSources.stringList = append(matchSources.stringList, scanner.Text())
		}
		c.LogInfo("remote source loaded with %d entries kind=%s", len(matchSources.stringList), srcKind)
	}

	return matchSources, nil
}

func (c *DNSMessage) LoadFromFile(filePath string, srcKind string) (MatchSource, error) {
	localFile := strings.TrimPrefix(filePath, "file://")

	c.LogInfo("loading matching source from file=%s", localFile)
	file, err := os.Open(localFile)
	if err != nil {
		return MatchSource{}, fmt.Errorf("unable to open file: %w", err)
	}

	matchSources := MatchSource{}
	scanner := bufio.NewScanner(file)

	switch srcKind {
	case dnsutils.MatchingKindRegexp:
		for scanner.Scan() {
			matchSources.regexList = append(matchSources.regexList, regexp.MustCompile(scanner.Text()))
		}
		c.LogInfo("file loaded with %d entries kind=%s", len(matchSources.regexList), srcKind)
	case dnsutils.MatchingKindString:
		for scanner.Scan() {
			matchSources.stringList = append(matchSources.stringList, scanner.Text())
		}
		c.LogInfo("file loaded with %d entries kind=%s", len(matchSources.stringList), srcKind)
	}

	return matchSources, nil
}

func (c *DNSMessage) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration...")
	c.configChan <- config
}

func (c *DNSMessage) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] collector=dnsmessage - "+msg, v...)
}

func (c *DNSMessage) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] collector=dnsmessage - "+msg, v...)
}

func (c *DNSMessage) Stop() {
	// c.LogInfo("stopping routing handler...")
	// c.RoutingHandler.Stop()

	// read done channel and block until run is terminated
	c.LogInfo("stopping run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping monitor...")
	c.stopMonitor <- true
	<-c.doneMonitor
}

func (c *DNSMessage) Run() {
	c.LogInfo("starting collector...")
	var err error

	// prepare next channels
	//defaultRoutes, defaultNames := c.RoutingHandler.GetDefaultRoutes()
	//droppedRoutes, droppedNames := c.RoutingHandler.GetDroppedRoutes()
	defaultRoutes, defaultNames := pkgutils.GetRoutes(c.defaultRoutes)
	droppedRoutes, droppedNames := pkgutils.GetRoutes(c.droppedRoutes)

	// prepare transforms
	subprocessors := transformers.NewTransforms(&c.config.IngoingTransformers, c.logger, c.name, defaultRoutes, 0)

	// start goroutine to count dropped messsages
	go c.MonitorNextStanzas()

	// read incoming dns message
	c.LogInfo("waiting dns message to process...")
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
			matchedExclude := false

			if len(c.config.Collectors.DNSMessage.Matching.Include) > 0 {
				err, matchedInclude = dm.Matching(c.config.Collectors.DNSMessage.Matching.Include)
				if err != nil {
					c.LogError(err.Error())
				}
				if matched && matchedInclude {
					matched = true
				} else {
					matched = false
				}
			}

			if len(c.config.Collectors.DNSMessage.Matching.Exclude) > 0 {
				err, matchedExclude = dm.Matching(c.config.Collectors.DNSMessage.Matching.Exclude)
				if err != nil {
					c.LogError(err.Error())
				}
				if matched && !matchedExclude {
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
					//c.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
					for i := range droppedRoutes {
						select {
						case droppedRoutes[i] <- dm:
						default:
							c.dropped <- droppedNames[i]
						}
					}
					continue
				}
			}

			// drop packet ?
			if !matched {
				//c.RoutingHandler.SendTo(droppedRoutes, droppedNames, dm)
				for i := range droppedRoutes {
					select {
					case droppedRoutes[i] <- dm:
					default:
						c.dropped <- droppedNames[i]
					}
				}
				continue
			}

			// send to next
			//c.RoutingHandler.SendTo(defaultRoutes, defaultNames, dm)
			for i := range defaultRoutes {
				select {
				case defaultRoutes[i] <- dm:
				default:
					c.dropped <- defaultNames[i]
				}
			}

		}

	}
	c.LogInfo("run terminated")
}

func (p *DNSMessage) MonitorNextStanzas() {
	watchInterval := 10 * time.Second
	bufferFull := time.NewTimer(watchInterval)
FOLLOW_LOOP:
	for {
		select {
		case <-p.stopMonitor:
			close(p.dropped)
			bufferFull.Stop()
			p.doneMonitor <- true
			break FOLLOW_LOOP

		case loggerName := <-p.dropped:
			if _, ok := p.droppedCount[loggerName]; !ok {
				p.droppedCount[loggerName] = 1
			} else {
				p.droppedCount[loggerName]++
			}

		case <-bufferFull.C:

			for v, k := range p.droppedCount {
				if k > 0 {
					p.LogError("stanza[%s] buffer is full, %d dnsmessage(s) dropped", v, k)
					p.droppedCount[v] = 0
				}
			}
			bufferFull.Reset(watchInterval)

		}
	}
	p.LogInfo("monitor terminated")
}
