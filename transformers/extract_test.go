package transformers

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
)

func TestExtract_Json(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()

	// get fake
	dm := dnsutils.GetFakeDnsMessage()
	dm.Init()

	// init subproccesor
	extract := NewExtractSubprocessor(config)
	extract.InitDnsMessage(&dm)

	// expected json
	refJson := `
			{
				"extracted":{
					"dns_payload": "LQ=="
				}
			}
			`

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJson()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJson), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if _, ok := dmMap["extracted"]; !ok {
		t.Fatalf("transformer key is missing")
	}

	if !reflect.DeepEqual(dmMap["extracted"], refMap["extracted"]) {
		t.Errorf("json format different from reference")
	}
}

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
