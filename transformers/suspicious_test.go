package transformers

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestSuspicious_Json(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()

	outChans := []chan dnsutils.DNSMessage{}

	// get fake
	dm := dnsutils.GetFakeDNSMessage()
	dm.Init()

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)
	suspicious.InitDNSMessage(&dm)

	// expected json
	refJSON := `
			{
				"suspicious": {
					"score":0,
					"malformed-pkt":false,
					"large-pkt":false,
					"long-domain":false,
					"slow-domain":false,
					"unallowed-chars":false,
					"uncommon-qtypes":false,
					"excessive-number-labels":false
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

	if _, ok := dmMap["suspicious"]; !ok {
		t.Fatalf("transformer key is missing")
	}

	if !reflect.DeepEqual(dmMap["suspicious"], refMap["suspicious"]) {
		t.Errorf("json format different from reference")
	}
}

func TestSuspicious_MalformedPacket(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)

	// malformed DNS message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.MalformedPacket = true

	// init dns message with additional part
	suspicious.InitDNSMessage(&dm)

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 0.0, got: %d", int(dm.Suspicious.Score))
	}

	if dm.Suspicious.MalformedPacket != true {
		t.Errorf("suspicious malformed packet flag should be equal to true")
	}
}

func TestSuspicious_LongDomain(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true
	config.Suspicious.ThresholdQnameLen = 4

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)

	// malformed DNS message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "longdomain.com"

	// init dns message with additional part
	suspicious.InitDNSMessage(&dm)

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 0.0, got: %d", int(dm.Suspicious.Score))
	}

	if dm.Suspicious.LongDomain != true {
		t.Errorf("suspicious long domain flag should be equal to true")
	}
}

func TestSuspicious_SlowDomain(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true
	config.Suspicious.ThresholdSlow = 3.0

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)

	// malformed DNS message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNSTap.Latency = 4.0

	// init dns message with additional part
	suspicious.InitDNSMessage(&dm)

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 0.0, got: %d", int(dm.Suspicious.Score))
	}

	if dm.Suspicious.SlowDomain != true {
		t.Errorf("suspicious slow domain flag should be equal to true")
	}
}

func TestSuspicious_LargePacket(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true
	config.Suspicious.ThresholdPacketLen = 4

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)

	// malformed DNS message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Length = 50

	// init dns message with additional part
	suspicious.InitDNSMessage(&dm)

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 0.0, got: %d", int(dm.Suspicious.Score))
	}

	if dm.Suspicious.LargePacket != true {
		t.Errorf("suspicious large packet flag should be equal to true")
	}
}

func TestSuspicious_UncommonQtype(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)

	// malformed DNS message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qtype = "LOC"

	// init dns message with additional part
	suspicious.InitDNSMessage(&dm)

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 0.0, got: %d", int(dm.Suspicious.Score))
	}

	if dm.Suspicious.UncommonQtypes != true {
		t.Errorf("suspicious uncommon qtype flag should be equal to true")
	}
}

func TestSuspicious_ExceedMaxLabels(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true
	config.Suspicious.ThresholdMaxLabels = 2

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)

	// malformed DNS message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "test.sub.dnscollector.com"

	// init dns message with additional part
	suspicious.InitDNSMessage(&dm)

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 0.0, got: %d", int(dm.Suspicious.Score))
	}

	if dm.Suspicious.ExcessiveNumberLabels != true {
		t.Errorf("suspicious excessive number labels flag should be equal to true")
	}
}

func TestSuspicious_UnallowedChars(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)

	// malformed DNS message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "AAAAAA==.dnscollector.com"

	// init dns message with additional part
	suspicious.InitDNSMessage(&dm)

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 1.0 {
		t.Errorf("suspicious score should be equal to 0.0, got: %d", int(dm.Suspicious.Score))
	}

	if dm.Suspicious.UnallowedChars != true {
		t.Errorf("suspicious unallowed chars flag should be equal to true")
	}
}

func TestSuspicious_WhitelistDomains(t *testing.T) {
	// config
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true

	outChans := []chan dnsutils.DNSMessage{}

	// init subproccesor
	suspicious := NewSuspiciousTransform(config, logger.New(false), "test", 0, outChans)

	// IPv6 DNS message PTR
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.ip6.arpa"

	// init dns message with additional part
	suspicious.InitDNSMessage(&dm)

	suspicious.CheckIfSuspicious(&dm)

	if dm.Suspicious.Score != 0.0 {
		t.Errorf("suspicious score should be equal to 0.0, got: %d", int(dm.Suspicious.Score))
	}
}
