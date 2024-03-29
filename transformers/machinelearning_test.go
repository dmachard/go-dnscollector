package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestML_AddFeatures(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.MachineLearning.Enable = true

	// init the processor
	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}
	transform := NewMachineLearningSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	dm := dnsutils.GetFakeDNSMessage()

	transform.InitDNSMessage(&dm)
	if dm.MachineLearning == nil {
		t.Errorf("DNSMessage.MachineLearning should be not nil")
	}

	transform.AddFeatures(&dm)
	if dm.MachineLearning.Labels != 2 {
		t.Errorf("incorrect feature label value in DNSMessage: %d", dm.MachineLearning.Labels)
	}
}