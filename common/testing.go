package common

import (
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

func GetFakeLogger(debug bool) *logger.Logger {
	logger := logger.New(debug)
	return logger
}

func GetFakeConfig() *Config {
	config := &Config{}
	config.SetDefault()
	return config
}

func GetFakeDnsMessage() dnsmessage.DnsMessage {
	dm := dnsmessage.DnsMessage{}
	dm.Init()
	dm.Identity = "collector"
	dm.Operation = "CLIENT_QUERY"
	dm.Type = "query"
	dm.Qname = "dns.collector"
	dm.QueryIp = "1.2.3.4"
	dm.QueryPort = "1234"
	dm.ResponseIp = "4.3.2.1"
	dm.ResponsePort = "4321"
	dm.Rcode = "NOERROR"
	dm.Qtype = "A"
	return dm
}
