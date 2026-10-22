package workers

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/transformers"
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
	*GenericWorker
	matcherInclude *dnsutils.CompiledMatcher
	matcherExclude *dnsutils.CompiledMatcher
}

func NewDNSMessage(next []Worker, cfg *config.Config, logger *logger.Logger, name string) *DNSMessage {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	s := &DNSMessage{GenericWorker: NewGenericWorker(cfg, logger, name, "dnsmessage", bufSize, config.DefaultMonitor)}
	s.SetDefaultRoutes(next)
	s.ReadConfig()
	return s
}

func (w *DNSMessage) ReadConfigMatching(value interface{}) {
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
			sourceData, err := w.LoadData(matchSrc, srcKind)
			if err != nil {
				w.LogFatal(err)
			}
			var sourceList interface{}
			if len(sourceData.regexList) > 0 {
				sourceList = sourceData.regexList
			}
			if len(sourceData.stringList) > 0 {
				sourceList = sourceData.stringList
			}
			if sourceList != nil {
				switch matchingMap := value.(type) {
				case map[string]interface{}:
					matchingMap[srcKind] = sourceList
				case map[interface{}]interface{}:
					matchingMap[srcKind] = sourceList
				default:
					w.LogError("unsupported matching configuration type: %T", value)
				}
			}
		}
	}
}

func (w *DNSMessage) ReadConfig() {
	// load external file for include
	if len(w.GetConfig().Collectors.DNSMessage.Matching.Include) > 0 {
		for _, value := range w.GetConfig().Collectors.DNSMessage.Matching.Include {
			w.ReadConfigMatching(value)
		}
		matcher, err := dnsutils.CompileMatcher(w.GetConfig().Collectors.DNSMessage.Matching.Include)
		if err != nil {
			w.LogError("failed to compile include matcher: %s", err)
		}
		w.matcherInclude = matcher
	} else {
		w.matcherInclude = nil
	}

	// load external file for exclude
	if len(w.GetConfig().Collectors.DNSMessage.Matching.Exclude) > 0 {
		for _, value := range w.GetConfig().Collectors.DNSMessage.Matching.Exclude {
			w.ReadConfigMatching(value)
		}
		matcher, err := dnsutils.CompileMatcher(w.GetConfig().Collectors.DNSMessage.Matching.Exclude)
		if err != nil {
			w.LogError("failed to compile exclude matcher: %s", err)
		}
		w.matcherExclude = matcher
	} else {
		w.matcherExclude = nil
	}
}

func (w *DNSMessage) LoadData(matchSource string, srcKind string) (MatchSource, error) {
	if isFileSource(matchSource) {
		dataSource, err := w.LoadFromFile(matchSource, srcKind)
		if err != nil {
			w.LogFatal(err)
		}
		return dataSource, nil
	} else if isURLSource(matchSource) {
		dataSource, err := w.LoadFromURL(matchSource, srcKind)
		if err != nil {
			w.LogFatal(err)
		}
		return dataSource, nil
	}
	return MatchSource{}, fmt.Errorf("match source not supported %s", matchSource)
}

func (w *DNSMessage) LoadFromURL(matchSource string, srcKind string) (MatchSource, error) {
	w.LogInfo("loading matching source from url=%s", matchSource)
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
		w.LogInfo("remote source loaded with %d entries kind=%s", len(matchSources.regexList), srcKind)
	case dnsutils.MatchingKindString:
		for scanner.Scan() {
			matchSources.stringList = append(matchSources.stringList, scanner.Text())
		}
		w.LogInfo("remote source loaded with %d entries kind=%s", len(matchSources.stringList), srcKind)
	}

	if err := scanner.Err(); err != nil {
		return MatchSource{}, fmt.Errorf("scanner error: %w", err)
	}

	return matchSources, nil
}

func (w *DNSMessage) LoadFromFile(filePath string, srcKind string) (MatchSource, error) {
	localFile := strings.TrimPrefix(filePath, "file://")

	w.LogInfo("loading matching source from file=%s", localFile)
	file, err := os.Open(localFile)
	if err != nil {
		return MatchSource{}, fmt.Errorf("unable to open file: %w", err)
	}
	defer file.Close()

	matchSources := MatchSource{}
	scanner := bufio.NewScanner(file)

	switch srcKind {
	case dnsutils.MatchingKindRegexp:
		for scanner.Scan() {
			matchSources.regexList = append(matchSources.regexList, regexp.MustCompile(scanner.Text()))
		}
		w.LogInfo("file loaded with %d entries kind=%s", len(matchSources.regexList), srcKind)
	case dnsutils.MatchingKindString:
		for scanner.Scan() {
			matchSources.stringList = append(matchSources.stringList, scanner.Text())
		}
		w.LogInfo("file loaded with %d entries kind=%s", len(matchSources.stringList), srcKind)
	}

	if err := scanner.Err(); err != nil {
		return MatchSource{}, fmt.Errorf("scanner error: %w", err)
	}

	return matchSources, nil
}

func (w *DNSMessage) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().IngoingTransformers, w.GetLogger(), w.GetName(), defaultRoutes, 0)

	// read incoming dns message
	w.LogInfo("waiting dns message to process...")
	for {
		select {
		case <-w.OnStop():
			subprocessors.Reset()
			return

		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()

		case batch, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("channel closed, exit")
				return
			}
			for _, dm := range batch.Messages {
				// count global messages
				w.CountIngressTraffic()

				// matching enabled, filtering DNS messages ?
				matched := true

				if w.matcherInclude != nil {
					if !w.matcherInclude.Match(dm) {
						matched = false
					}
				}

				if matched && w.matcherExclude != nil {
					if w.matcherExclude.Match(dm) {
						matched = false
					}
				}

				// count output packets
				w.CountEgressTraffic()

				// apply transform on matched packets only
				// init dns message with additional parts if necessary
				if matched {
					transformResult, err := subprocessors.ProcessMessage(dm)
					if err != nil {
						w.LogError(err.Error())
					}
					if transformResult == transformers.ReturnDrop {
						w.SendDroppedTo(droppedRoutes, droppedNames, dm)
						continue
					}
				}

				// drop packet ?
				if !matched {
					w.SendDroppedTo(droppedRoutes, droppedNames, dm)
					continue
				}

				// send to next
				w.SendForwardedTo(defaultRoutes, defaultNames, dm)
			}
			batch.Release()
		}
	}
}

func init() {
	RegisterCollector("dnsmessage", func(c *config.Config) bool { return c.Collectors.DNSMessage.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewDNSMessage(nil, c, l, s)
	})
}
