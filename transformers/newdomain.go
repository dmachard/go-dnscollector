package transformers

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	lru "github.com/hashicorp/golang-lru"
)

// NewDomainTracker transformer to detect newly observed domains
type NewDomainTracker struct {
	ttl       time.Duration             // Time window to consider a domain as "new"
	cache     *lru.Cache                // LRU Cache to store observed domains
	whitelist map[string]*regexp.Regexp // Whitelisted domains
	logInfo   func(msg string, v ...interface{})
	logError  func(msg string, v ...interface{})
}

// NewNewDomainTracker initializes the NewDomainTracker transformer
func NewNewDomainTracker(ttl time.Duration, maxSize int, whitelist map[string]*regexp.Regexp, logInfo, logError func(msg string, v ...interface{})) (*NewDomainTracker, error) {
	cache, err := lru.New(maxSize)
	if err != nil {
		return nil, err
	}

	if ttl <= 0 {
		return nil, fmt.Errorf("invalid TTL value: %v", ttl)
	}

	return &NewDomainTracker{
		ttl:       ttl,
		cache:     cache,
		whitelist: whitelist,
		logInfo:   logInfo,
		logError:  logError,
	}, nil
}

// isWhitelisted checks if a domain or its subdomain is in the whitelist
func (ndt *NewDomainTracker) isWhitelisted(domain string) bool {
	for _, d := range ndt.whitelist {
		if d.MatchString(domain) {
			return true
		}
	}
	return false
}

// IsNewDomain checks if the domain is newly observed
func (ndt *NewDomainTracker) IsNewDomain(domain string) bool {
	// Check if the domain is whitelisted
	if ndt.isWhitelisted(domain) {
		return false
	}

	now := time.Now()

	// Check if the domain exists in the cache
	if lastSeen, exists := ndt.cache.Get(domain); exists {
		fmt.Println("exists")
		if now.Sub(lastSeen.(time.Time)) < ndt.ttl {
			fmt.Println(now.Sub(lastSeen.(time.Time)), ndt.ttl)
			// Domain was recently seen, not new
			return false
		}
	}

	// Otherwise, mark the domain as new and update the cache
	ndt.cache.Add(domain, now)
	return true
}

// NewDomainTransform is the Transformer for DNS messages
type NewDomainTrackerTransform struct {
	GenericTransformer
	domainTracker    *NewDomainTracker
	listDomainsRegex map[string]*regexp.Regexp
}

// NewNewDomainTransform creates a new instance of the transformer
func NewNewDomainTrackerTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *NewDomainTrackerTransform {
	t := &NewDomainTrackerTransform{GenericTransformer: NewTransformer(config, logger, "new-domain-tracker", name, instance, nextWorkers)}
	t.listDomainsRegex = make(map[string]*regexp.Regexp)
	return t
}

// ReloadConfig reloads the configuration
func (t *NewDomainTrackerTransform) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	t.GenericTransformer.ReloadConfig(config)
	ttl := time.Duration(config.NewDomainTracker.TTL) * time.Second
	t.domainTracker.ttl = ttl
	t.LogInfo("new-domain-transformer configuration reloaded")
}

func (t *NewDomainTrackerTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.NewDomainTracker.Enable {
		// init whitelist
		if err := t.LoadWhiteDomainsList(); err != nil {
			return nil, err
		}

		// Initialize the domain tracker
		ttl := time.Duration(t.config.NewDomainTracker.TTL) * time.Second
		maxSize := t.config.NewDomainTracker.CacheSize
		tracker, err := NewNewDomainTracker(ttl, maxSize, t.listDomainsRegex, t.LogInfo, t.LogError)
		if err != nil {
			return nil, err
		}
		t.domainTracker = tracker

		subtransforms = append(subtransforms, Subtransform{name: "new-domain-tracker:detect", processFunc: t.trackNewDomain})
	}
	return subtransforms, nil
}

func (t *NewDomainTrackerTransform) LoadWhiteDomainsList() error {
	// before to start, reset all maps
	for key := range t.listDomainsRegex {
		delete(t.listDomainsRegex, key)
	}

	if len(t.config.NewDomainTracker.WhiteDomainsFile) > 0 {
		file, err := os.Open(t.config.NewDomainTracker.WhiteDomainsFile)
		if err != nil {
			return fmt.Errorf("unable to open regex list file: %w", err)
		} else {

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				domain := strings.ToLower(scanner.Text())
				t.listDomainsRegex[domain] = regexp.MustCompile(domain)
			}
			t.LogInfo("loaded with %d domains in the whitelist", len(t.listDomainsRegex))
		}
	}
	return nil
}

// Process processes DNS messages and detects newly observed domains
func (t *NewDomainTrackerTransform) trackNewDomain(dm *dnsutils.DNSMessage) (int, error) {
	// Check if the domain is newly observed
	if t.domainTracker.IsNewDomain(dm.DNS.Qname) {
		return ReturnKeep, nil
	}
	return ReturnDrop, nil
}
