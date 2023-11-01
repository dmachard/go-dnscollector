package dnsutils

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestConfigClientTLSNoVerify(t *testing.T) {
	tlsConfig, err := TlsClientConfig(TlsOptions{InsecureSkipVerify: true})

	if err != nil || tlsConfig == nil {
		t.Fatal("Unable to configure client TLS", err)
	}

	if !reflect.DeepEqual(tlsConfig.CipherSuites, clientCipherSuites) {
		t.Fatal("Unexpected client cipher suites")
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("Unexpected client TLS version")
	}

	if tlsConfig.Certificates != nil {
		t.Fatal("Somehow client certificates were set")
	}
}
