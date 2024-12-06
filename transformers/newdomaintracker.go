package transformers

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

type NewDomainTracker struct {
	ttl             time.Duration                    // Time window to consider a domain as "new"
	cache           *expirable.LRU[string, struct{}] // Expirable LRU Cache
	whitelist       map[string]*regexp.Regexp        // Whitelisted domains
	persistencePath string
	logInfo         func(msg string, v ...interface{})
	logError        func(msg string, v ...interface{})
}

func NewNewDomainTracker(ttl time.Duration, maxSize int, whitelist map[string]*regexp.Regexp, persistencePath string, logInfo, logError func(msg string, v ...interface{})) (*NewDomainTracker, error) {

	if ttl <= 0 {
		return nil, fmt.Errorf("invalid TTL value: %v", ttl)
	}

	cache := expirable.NewLRU[string, struct{}](maxSize, nil, ttl)

	tracker := &NewDomainTracker{
		ttl:             ttl,
		cache:           cache,
		whitelist:       whitelist,
		persistencePath: persistencePath,
		logInfo:         logInfo,
		logError:        logError,
	}
	// Load cache state from disk if persistence is enabled
	if persistencePath != "" {
		if err := tracker.loadCacheFromDisk(); err != nil {
			return nil, fmt.Errorf("failed to load cache state: %w", err)
		}
	}

	return tracker, nil
}

func (ndt *NewDomainTracker) isWhitelisted(domain string) bool {
	for _, d := range ndt.whitelist {
		if d.MatchString(domain) {
			return true
		}
	}
	return false
}

func (ndt *NewDomainTracker) IsNewDomain(domain string) bool {
	// Check if the domain is whitelisted
	if ndt.isWhitelisted(domain) {
		return false
	}

	// Check if the domain exists in the cache
	if _, exists := ndt.cache.Get(domain); exists {
		// Domain was recently seen, not new
		return false
	}

	// Otherwise, mark the domain as new
	ndt.cache.Add(domain, struct{}{})
	return true
}

func (ndt *NewDomainTracker) SaveCacheToDisk() error {
	keys := ndt.cache.Keys()
	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}

	return os.WriteFile(ndt.persistencePath, data, 0644)
}

// loadCacheFromDisk loads the cache state from a file
func (ndt *NewDomainTracker) loadCacheFromDisk() error {
	if ndt.persistencePath == "" {
		return errors.New("persistence filepath not set")
	}

	data, err := os.ReadFile(ndt.persistencePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File does not exist, no previous state to load
		}
		return err
	}

	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}

	for _, key := range keys {
		ndt.cache.Add(key, struct{}{})
	}

	return nil
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
		tracker, err := NewNewDomainTracker(ttl, maxSize, t.listDomainsRegex, t.config.NewDomainTracker.PersistenceFile, t.LogInfo, t.LogError)
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
	// Log a warning if the cache is full (before adding the new domain)
	if t.domainTracker.cache.Len() == t.config.NewDomainTracker.CacheSize {
		return ReturnError, fmt.Errorf("LRU cache is full. Consider increasing cache-size to avoid frequent evictions")
	}

	// Check if the domain is newly observed
	if t.domainTracker.IsNewDomain(dm.DNS.Qname) {
		return ReturnKeep, nil
	}
	return ReturnDrop, nil
}

func (t *NewDomainTrackerTransform) Reset() {
	if len(t.domainTracker.persistencePath) != 0 {
		if err := t.domainTracker.SaveCacheToDisk(); err != nil {
			t.LogError("failed to save cache state: %v", err)
		}
		t.LogInfo("cache content saved on disk with success")
	}
}
