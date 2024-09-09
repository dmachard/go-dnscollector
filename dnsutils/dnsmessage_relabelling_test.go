package dnsutils

import (
	"reflect"
	"regexp"
	"testing"
)

// Flatten and relabeling
func TestDnsMessage_ApplyRelabeling(t *testing.T) {
	// Créer un DNSMessage avec des règles de relabeling pour le test
	dm := &DNSMessage{
		Relabeling: &TransformRelabeling{
			Rules: []RelabelingRule{
				{Regex: regexp.MustCompile("^old_"), Replacement: "new_field", Action: "rename"},
				{Regex: regexp.MustCompile("^foo_"), Action: "remove"},
			},
		},
	}

	// test map
	dnsFields := map[string]interface{}{
		"old_field":   "value1",
		"foo_field":   "value2",
		"other_field": "value3",
	}

	// apply relabeling
	err := dm.ApplyRelabeling(dnsFields)
	if err != nil {
		t.Errorf("ApplyRelabeling() return an error: %v", err)
	}

	// check
	expectedDNSFields := map[string]interface{}{
		"new_field":   "value1",
		"other_field": "value3",
	}
	if !reflect.DeepEqual(dnsFields, expectedDNSFields) {
		t.Errorf("Want: %v, Get: %v", expectedDNSFields, dnsFields)
	}
}

func BenchmarkDnsMessage_ToFlatten_Relabelling(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	dm.Relabeling.Rules = append(dm.Relabeling.Rules, RelabelingRule{
		Regex:  regexp.MustCompile(`dns.qname`),
		Action: "remove",
	})
	dm.Relabeling.Rules = append(dm.Relabeling.Rules, RelabelingRule{
		Regex:       regexp.MustCompile(`dns.qtype`),
		Replacement: "qtype",
		Action:      "rename",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.Flatten()
		if err != nil {
			b.Fatalf("could not flat: %v\n", err)
		}
	}
}

func BenchmarkDnsMessage_ToFlatten(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.Flatten()
		if err != nil {
			b.Fatalf("could not flat: %v\n", err)
		}
	}
}
