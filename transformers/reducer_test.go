package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestReducer_RepetitiveTrafficDetector(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Reducer.Enable = true
	config.Reducer.RepetitiveTrafficDetector = true

}
