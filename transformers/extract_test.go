package transformers

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestExtract_AddPayload(t *testing.T) {
	// enable geoip
	config := dnsutils.GetFakeConfigTransformers()
	config.Extract.Enable = true
	config.Extract.AddPayload = true

	// init the processor
	extract := NewExtractSubprocessor(config)

	// feature is enabled ?
	if !extract.IsEnabled() {
		t.Fatalf("extract should be enabled")
	}

	dm := dnsutils.GetFakeDnsMessage()
	src := []byte("P6CBgAABAAEAAAABD29yYW5nZS1zYW5ndWluZQJmcgAAAQABwAwAAQABAABUYAAEwcvvUQAAKQTQAAAAAAAA")
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	base64.StdEncoding.Decode(dst, src)
	dm.DNS.Payload = dst
	if reflect.DeepEqual(extract.AddBase64Payload(&dm), src) {
		t.Errorf("dns payload base64 encoding should match.")
	}
}
