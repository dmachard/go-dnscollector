package processors

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func Test_PowerDNSProcessor(t *testing.T) {
	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, pkgconfig.GetFakeConfig(), logger.New(false), "test", 512)

	// init the powerdns processor
	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-fl.GetInputChannel()
	if msg.DNSTap.Identity != "powerdnspb" {
		t.Errorf("invalid identity in dns message: %s", msg.DNSTap.Identity)
	}
}

func Test_PowerDNSProcessor_AddDNSPayload_Valid(t *testing.T) {
	cfg := pkgconfig.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the powerdns processor
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)

	// prepare powerdns message
	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Id = proto.Uint32(2000)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// start the consumer and add packet
	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	consumer.GetChannel() <- data

	// read dns message
	msg := <-fl.GetInputChannel()

	// checks
	if msg.DNS.Length == 0 {
		t.Errorf("invalid length got %d", msg.DNS.Length)
	}
	if len(msg.DNS.Payload) == 0 {
		t.Errorf("invalid payload length %d", len(msg.DNS.Payload))
	}

	// valid dns payload ?
	var decodedPayload dns.Msg
	err := decodedPayload.Unpack(msg.DNS.Payload)
	if err != nil {
		t.Errorf("unpack error %s", err)
	}
	if decodedPayload.Question[0].Name != pkgconfig.ValidDomain {
		t.Errorf("invalid qname in payload: %s", decodedPayload.Question[0].Name)
	}
}

func Test_PowerDNSProcessor_AddDNSPayload_InvalidLabelLength(t *testing.T) {
	cfg := pkgconfig.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)

	// prepare dnstap
	dnsQname := pkgconfig.BadDomainLabel
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Id = proto.Uint32(2000)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-fl.GetInputChannel()
	if !msg.DNS.MalformedPacket {
		t.Errorf("DNS message should malformed")
	}
}

func Test_PowerDNSProcessor_AddDNSPayload_QnameTooLongDomain(t *testing.T) {
	cfg := pkgconfig.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)

	// prepare dnstap
	dnsQname := pkgconfig.BadVeryLongDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-fl.GetInputChannel()
	if !msg.DNS.MalformedPacket {
		t.Errorf("DNS message should malformed because of qname too long")
	}
}

func Test_PowerDNSProcessor_AddDNSPayload_AnswersTooLongDomain(t *testing.T) {
	cfg := pkgconfig.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)

	// prepare dnstap
	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	rrQname := pkgconfig.BadVeryLongDomain
	rrDNS := powerdns_protobuf.PBDNSMessage_DNSResponse_DNSRR{
		Name:  &rrQname,
		Class: proto.Uint32(1),
		Type:  proto.Uint32(1),
		Rdata: []byte{0x01, 0x00, 0x00, 0x01},
	}
	dnsReply := powerdns_protobuf.PBDNSMessage_DNSResponse{}
	dnsReply.Rrs = append(dnsReply.Rrs, &rrDNS)

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSResponseType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion
	dm.Response = &dnsReply

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	fl := loggers.NewFakeLogger()
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-fl.GetInputChannel()

	// tests verifications
	if !msg.DNS.MalformedPacket {
		t.Errorf("DNS message is not malformed")
	}
}

// test for issue https://github.com/dmachard/go-dnscollector/issues/568
func Test_PowerDNSProcessor_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 10)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the dnstap consumer
	cfg := pkgconfig.GetFakeConfig()
	consumer := NewPdnsProcessor(0, cfg, lg, "test", 512)

	// init the powerdns processor
	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	fl := loggers.NewFakeLoggerWithBufferSize(1)
	go consumer.Run([]pkgutils.Worker{fl}, []pkgutils.Worker{fl})

	// add packets to consumer
	for i := 0; i < 512; i++ {
		consumer.GetChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	regxp := ".*buffer is full, 511.*"
	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(regxp)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	msg := <-fl.GetInputChannel()
	if msg.DNSTap.Identity != "powerdnspb" {
		t.Errorf("invalid identity in dns message: %s", msg.DNSTap.Identity)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		consumer.GetChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)
	regxp = ".*buffer is full, 1023.*"
	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(regxp)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read just one dns message from dnstap consumer
	msg2 := <-fl.GetInputChannel()
	if msg2.DNSTap.Identity != "powerdnspb" {
		t.Errorf("invalid identity in second dns message: %s", msg2.DNSTap.Identity)
	}
}
