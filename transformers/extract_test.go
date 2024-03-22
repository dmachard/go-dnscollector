package transformers

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestExtract_Json(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}
	outChans = append(outChans, make(chan dnsutils.DNSMessage, 1))

	// get fake
	dm := dnsutils.GetFakeDNSMessage()
	dm.Init()

	// init subproccesor
	extract := NewExtractSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	extract.InitDNSMessage(&dm)

	// expected json
	refJSON := `
			{
				"extracted":{
					"dns_payload": "LQ=="
				}
			}
			`

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJSON()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJSON), &refMap)
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
	config := pkgconfig.GetFakeConfigTransformers()
	config.Extract.Enable = true
	config.Extract.AddPayload = true

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{}

	// init the processor
	extract := NewExtractSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)

	// feature is enabled ?
	if !extract.IsEnabled() {
		t.Fatalf("extract should be enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	src := []byte("P6CBgAABAAEAAAABD29yYW5nZS1zYW5ndWluZQJmcgAAAQABwAwAAQABAABUYAAEwcvvUQAAKQTQAAAAAAAA")
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	base64.StdEncoding.Decode(dst, src)
	dm.DNS.Payload = dst
	if reflect.DeepEqual(extract.AddBase64Payload(&dm), src) {
		t.Errorf("dns payload base64 encoding should match.")
	}
}
