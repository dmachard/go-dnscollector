package common

import (
	"bytes"

	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

func GetFakeLogger(debug bool) (*logger.Logger, bytes.Buffer) {
	logger := logger.New(debug)
	var o bytes.Buffer
	logger.SetOutput(&o)
	return logger, o
}

func GetFakeConfig() *Config {
	config := &Config{}
	return config
}

func GetFakeDnsMessage() dnsmessage.DnsMessage {
	dm := dnsmessage.DnsMessage{}
	dm.Init()
	dm.Operation = "CLIENT_QUERY"
	dm.Type = "query"
	dm.Qname = "dns.collector"
	dm.QueryIp = "1.2.3.4"
	dm.Rcode = "NOERROR"
	dm.Qtype = "A"
	return dm
}
