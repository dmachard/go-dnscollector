package dnsutils

import (
	"testing"

	"github.com/dmachard/go-dnstap-protobuf"
	"google.golang.org/protobuf/proto"
)

// Tests for DNSTap format
func encodeToDNSTap(dm DNSMessage, t *testing.T) *ExtendedDnstap {
	// encode to extended dnstap
	tapMsg, err := dm.ToDNSTap(true)
	if err != nil {
		t.Fatalf("could not encode to extended dnstap: %v\n", err)
	}

	// decode dnstap message
	dt := &dnstap.Dnstap{}
	err = proto.Unmarshal(tapMsg, dt)
	if err != nil {
		t.Fatalf("error to decode dnstap: %v", err)
	}

	// decode extended part
	edt := &ExtendedDnstap{}
	err = proto.Unmarshal(dt.GetExtra(), edt)
	if err != nil {
		t.Fatalf("error to decode extended dnstap: %v", err)
	}
	return edt
}

func TestDnsMessage_ToDNSTap(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.DNSTap.Extra = "extra:value"

	// encode to dnstap
	tapMsg, err := dm.ToDNSTap(false)
	if err != nil {
		t.Fatalf("could not encode to dnstap: %v\n", err)
	}

	// decode dnstap message
	dt := &dnstap.Dnstap{}
	err = proto.Unmarshal(tapMsg, dt)
	if err != nil {
		t.Fatalf("error to decode dnstap: %v", err)
	}

	if string(dt.GetIdentity()) != dm.DNSTap.Identity {
		t.Errorf("identify field should be equal got=%s", string(dt.GetIdentity()))
	}

	if string(dt.GetExtra()) != dm.DNSTap.Extra {
		t.Errorf("extra field should be equal got=%s", string(dt.GetExtra()))
	}
}

func BenchmarkDnsMessage_ToDNSTap(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.ToDNSTap(false)
		if err != nil {
			b.Fatalf("could not encode to dnstap: %v\n", err)
		}
	}
}

// Tests for Extended DNSTap format
func TestDnsMessage_ToExtendedDNSTap_GetOriginalDnstapExtra(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.DNSTap.Extra = "tag0:value0"

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// check
	if string(edt.GetOriginalDnstapExtra()) != dm.DNSTap.Extra {
		t.Errorf("extra field should be equal to the original value")
	}
}

func TestDnsMessage_ToExtendedDNSTap_TransformAtags(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.ATags = &TransformATags{
		Tags: []string{"tag1:value1"},
	}

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// check
	if edt.GetAtags().Tags[0] != "tag1:value1" {
		t.Errorf("invalid value on atags")
	}
}

func TestDnsMessage_ToExtendedDNSTap_TransformNormalize(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.PublicSuffix = &TransformPublicSuffix{
		QnamePublicSuffix:        "com",
		QnameEffectiveTLDPlusOne: "dnscollector.com",
	}

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// checks
	if edt.GetNormalize().GetTld() != "com" {
		t.Errorf("invalid value on tld")
	}

	if edt.GetNormalize().GetEtldPlusOne() != "dnscollector.com" {
		t.Errorf("invalid value on etld+1")
	}
}

func TestDnsMessage_ToExtendedDNSTap_TransformFiltering(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.Filtering = &TransformFiltering{
		SampleRate: 20,
	}

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// checks
	if edt.GetFiltering().GetSampleRate() != 20 {
		t.Errorf("invalid value sample rate")
	}
}

func TestDnsMessage_ToExtendedDNSTap_TransformGeo(t *testing.T) {
	dm := GetFakeDNSMessageWithPayload()
	dm.Geo = &TransformDNSGeo{
		City:                   "France",
		Continent:              "Europe",
		CountryIsoCode:         "44444",
		AutonomousSystemNumber: "3333",
		AutonomousSystemOrg:    "Test",
	}

	// encode to DNSTap and decode extended
	edt := encodeToDNSTap(dm, t)

	// checks
	if edt.GetGeo().GetCity() != "France" {
		t.Errorf("invalid value for city")
	}
	if edt.GetGeo().GetContinent() != "Europe" {
		t.Errorf("invalid value for continent")
	}
}

func BenchmarkDnsMessage_ToExtendedDNSTap(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.ToDNSTap(true)
		if err != nil {
			b.Fatalf("could not encode to extended dnstap: %v\n", err)
		}
	}
}
