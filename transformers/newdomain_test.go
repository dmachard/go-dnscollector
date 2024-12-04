package transformers

import (
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestNewDomainTracker(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.NewDomainTracker.Enable = true
	config.NewDomainTracker.TTL = 2
	config.NewDomainTracker.CacheSize = 10

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	tracker := NewNewDomainTrackerTransform(config, logger.New(false), "test", 0, outChans)

	// init transforms
	_, err := tracker.GetTransforms()
	if err != nil {
		t.Error("fail to init transform", err)
	}

	// first send
	dm := dnsutils.GetFakeDNSMessage()
	if result, _ := tracker.trackNewDomain(&dm); result != ReturnKeep {
		t.Errorf("1. this domain should be new!!")
	}
	if result, _ := tracker.trackNewDomain(&dm); result != ReturnDrop {
		t.Errorf("2. this domain should NOT be new!!")
	}

	// wait ttl for expiration
	time.Sleep(3 * time.Second)

	// recheck
	if result, _ := tracker.trackNewDomain(&dm); result != ReturnKeep {
		t.Errorf("3. this domain should be new!!")
	}

}
