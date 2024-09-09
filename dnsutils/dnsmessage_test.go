package dnsutils

import (
	"testing"
)

// Bench to init DNS message
func BenchmarkDnsMessage_Init(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm := DNSMessage{}
		dm.Init()
		dm.InitTransforms()
	}
}
