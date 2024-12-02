package transformers

import (
	"fmt"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	lru "github.com/hashicorp/golang-lru"
)

// NewDomainTracker transformer to detect newly observed domains
type NewDomainTracker struct {
	ttl      time.Duration // Time window to consider a domain as "new"
	cache    *lru.Cache    // LRU Cache to store observed domains
	logInfo  func(msg string, v ...interface{})
	logError func(msg string, v ...interface{})
}

// NewNewDomainTracker initializes the NewDomainTracker transformer
func NewNewDomainTracker(ttl time.Duration, maxSize int, logInfo, logError func(msg string, v ...interface{})) (*NewDomainTracker, error) {
	cache, err := lru.New(maxSize)
	if err != nil {
		return nil, err
	}

	if ttl <= 0 {
		return nil, fmt.Errorf("invalid TTL value: %v", ttl)
	}

	return &NewDomainTracker{
		ttl:      ttl,
		cache:    cache,
		logInfo:  logInfo,
		logError: logError,
	}, nil
}

// IsNewDomain checks if the domain is newly observed
func (ndt *NewDomainTracker) IsNewDomain(domain string) bool {
	now := time.Now()

	// Check if the domain exists in the cache
	if lastSeen, exists := ndt.cache.Get(domain); exists {
		if now.Sub(lastSeen.(time.Time)) < ndt.ttl {
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
	domainTracker *NewDomainTracker
}

// NewNewDomainTransform creates a new instance of the transformer
func NewNewDomainTrackerTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *NewDomainTrackerTransform {
	t := &NewDomainTrackerTransform{GenericTransformer: NewTransformer(config, logger, "new-domain-tracker", name, instance, nextWorkers)}

	// Initialize the domain tracker
	ttl := time.Duration(config.NewDomainTracker.TTL) * time.Second
	maxSize := config.NewDomainTracker.CacheSize
	tracker, err := NewNewDomainTracker(ttl, maxSize, t.LogInfo, t.LogError)
	if err != nil {
		t.LogError("failed to initialize NewDomainTracker: %v", err)
		return nil
	}

	t.domainTracker = tracker
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
		subtransforms = append(subtransforms, Subtransform{name: "new-domain-tracker:detect", processFunc: t.trackNewDomain})
	}
	return subtransforms, nil
}

// Process processes DNS messages and detects newly observed domains
func (t *NewDomainTrackerTransform) trackNewDomain(dm *dnsutils.DNSMessage) (int, error) {
	// Check if the domain is newly observed
	if t.domainTracker.IsNewDomain(dm.DNS.Qname) {
		return ReturnKeep, nil
	}
	return ReturnDrop, nil
}
