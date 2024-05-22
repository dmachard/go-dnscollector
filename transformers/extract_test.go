package transformers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestExtract_Json(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	outChans := []chan dnsutils.DNSMessage{}
	outChans = append(outChans, make(chan dnsutils.DNSMessage, 1))

	// get dns message
	dm := dnsutils.GetFakeDNSMessageWithPayload()

	// init subproccesor
	extract := NewExtractTransform(config, logger.New(false), "test", 0, outChans)
	extract.GetTransforms()
	extract.addBase64Payload(&dm)

	encodedPayload := base64.StdEncoding.EncodeToString(dm.DNS.Payload)

	// expected json
	refJSON := fmt.Sprintf(`
			{
				"extracted":{
					"dns_payload": "%s"
				}
			}
			`, encodedPayload)

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
