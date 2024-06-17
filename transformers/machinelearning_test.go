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
	outChans := []chan dnsutils.DNSMessage{}
	ml := NewMachineLearningTransform(config, logger.New(false), "test", 0, outChans)

	dm := dnsutils.GetFakeDNSMessage()

	// init transforms and check
	ml.GetTransforms()
	ml.addFeatures(&dm)

	if dm.MachineLearning.Labels != 2 {
		t.Errorf("incorrect feature label value in DNSMessage: %d", dm.MachineLearning.Labels)
	}
}
