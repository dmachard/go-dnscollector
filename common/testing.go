package common

import (
	"net"
	"time"

	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-logger"
	"github.com/miekg/dns"
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

func GetFakeDnstap(dnsquery []byte) *dnstap.Dnstap {
	dt_query := &dnstap.Dnstap{}

	dt := dnstap.Dnstap_MESSAGE
	dt_query.Identity = []byte("dnstap-generator")
	dt_query.Version = []byte("-")
	dt_query.Type = &dt

	mt := dnstap.Message_CLIENT_QUERY
	sf := dnstap.SocketFamily_INET
	sp := dnstap.SocketProtocol_UDP

	now := time.Now()
	tsec := uint64(now.Unix())
	tnsec := uint32(uint64(now.UnixNano()) - uint64(now.Unix())*1e9)

	rport := uint32(53)
	qport := uint32(5300)

	msg := &dnstap.Message{Type: &mt}
	msg.SocketFamily = &sf
	msg.SocketProtocol = &sp
	msg.QueryAddress = net.ParseIP("127.0.0.1")
	msg.QueryPort = &qport
	msg.ResponseAddress = net.ParseIP("127.0.0.2")
	msg.ResponsePort = &rport

	msg.QueryMessage = dnsquery
	msg.QueryTimeSec = &tsec
	msg.QueryTimeNsec = &tnsec

	dt_query.Message = msg
	return dt_query
}

func GetFakeDns() ([]byte, error) {
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dns.collector.", dns.TypeA)
	return dnsmsg.Pack()
}

type FakeGen struct {
	channel chan dnsmessage.DnsMessage
}

func NewFakeGenerator() *FakeGen {
	o := &FakeGen{
		channel: make(chan dnsmessage.DnsMessage, 512),
	}
	return o
}

func (o *FakeGen) Stop() {}

func (o *FakeGen) Channel() chan dnsmessage.DnsMessage {
	return o.channel
}

func (o *FakeGen) Run() {}
