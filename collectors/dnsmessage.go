package collectors

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"

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
	*pkgutils.GenericWorker
	inputChan chan dnsutils.DNSMessage
}

func NewDNSMessage(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *DNSMessage {
	s := &DNSMessage{
		GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "dnsmessage", 0),
		inputChan:     make(chan dnsutils.DNSMessage, config.Collectors.DNSMessage.ChannelBufferSize),
	}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
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
				c.LogFatal(err)
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

func (c *DNSMessage) ReadConfig() {
	// load external file for include
	if len(c.GetConfig().Collectors.DNSMessage.Matching.Include) > 0 {
		for _, value := range c.GetConfig().Collectors.DNSMessage.Matching.Include {
			c.ReadConfigMatching(value)
		}
	}
	// load external file for exclude
	if len(c.GetConfig().Collectors.DNSMessage.Matching.Exclude) > 0 {
		for _, value := range c.GetConfig().Collectors.DNSMessage.Matching.Exclude {
			c.ReadConfigMatching(value)
		}
	}
}

func (c *DNSMessage) GetInputChannel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *DNSMessage) LoadData(matchSource string, srcKind string) (MatchSource, error) {
	if isFileSource(matchSource) {
		dataSource, err := c.LoadFromFile(matchSource, srcKind)
		if err != nil {
			c.LogFatal(err)
		}
		return dataSource, nil
	} else if isURLSource(matchSource) {
		dataSource, err := c.LoadFromURL(matchSource, srcKind)
		if err != nil {
			c.LogFatal(err)
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

func (c *DNSMessage) StartCollect() {
	c.LogInfo("worker is starting collection")
	defer c.CollectDone()

	var err error

	// prepare next channels
	defaultRoutes, defaultNames := pkgutils.GetRoutes(c.GetDefaultRoutes())
	droppedRoutes, droppedNames := pkgutils.GetRoutes(c.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&c.GetConfig().IngoingTransformers, c.GetLogger(), c.GetName(), defaultRoutes, 0)

	// read incoming dns message
	c.LogInfo("waiting dns message to process...")
	for {
		select {
		case <-c.OnStop():
			return

		// save the new config
		case cfg := <-c.NewConfig():
			c.SetConfig(cfg)
			c.ReadConfig()

		case dm, opened := <-c.GetInputChannel():
			if !opened {
				c.LogInfo("channel closed, exit")
				return
			}

			// matching enabled, filtering DNS messages ?
			matched := true
			matchedInclude := false
			matchedExclude := false

			if len(c.GetConfig().Collectors.DNSMessage.Matching.Include) > 0 {
				err, matchedInclude = dm.Matching(c.GetConfig().Collectors.DNSMessage.Matching.Include)
				if err != nil {
					c.LogError(err.Error())
				}
				if matched && matchedInclude {
					matched = true
				} else {
					matched = false
				}
			}

			if len(c.GetConfig().Collectors.DNSMessage.Matching.Exclude) > 0 {
				err, matchedExclude = dm.Matching(c.GetConfig().Collectors.DNSMessage.Matching.Exclude)
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
					c.SendTo(droppedRoutes, droppedNames, dm)
					continue
				}
			}

			// drop packet ?
			if !matched {
				c.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to next
			c.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}
