package pkgconfig

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestConfigClientTLSNoVerify(t *testing.T) {
	tlsConfig, err := TLSClientConfig(TLSOptions{InsecureSkipVerify: true, MinVersion: TLSV12})

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
