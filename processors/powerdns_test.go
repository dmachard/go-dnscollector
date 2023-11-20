package processors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func TestPowerDNS_Processor(t *testing.T) {
	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, dnsutils.GetFakeConfig(), logger.New(false), "test", 512)
	chanTo := make(chan dnsutils.DNSMessage, 512)

	// init the powerdns processor
	dnsQname := dnsutils.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-chanTo
	if msg.DNSTap.Identity != "powerdnspb" {
		t.Errorf("invalid identity in dns message: %s", msg.DNSTap.Identity)
	}
}

func TestPowerDNS_Processor_AddDNSPayload_Valid(t *testing.T) {
	cfg := dnsutils.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the powerdns processor
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)
	chanTo := make(chan dnsutils.DNSMessage, 1)

	// prepare powerdns message
	dnsQname := dnsutils.ValidDomain
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
	go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})
	consumer.GetChannel() <- data

	// read dns message
	msg := <-chanTo

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
	if decodedPayload.Question[0].Name != dnsutils.ValidDomain {
		t.Errorf("invalid qname in payload: %s", decodedPayload.Question[0].Name)
	}
}

func TestPowerDNS_Processor_AddDNSPayload_InvalidLabelLength(t *testing.T) {
	cfg := dnsutils.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)
	chanTo := make(chan dnsutils.DNSMessage, 512)

	// prepare dnstap
	dnsQname := dnsutils.BadDomainLabel
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Id = proto.Uint32(2000)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-chanTo
	if !msg.DNS.MalformedPacket {
		t.Errorf("DNS message should malformed")
	}
}

func TestPowerDNS_Processor_AddDNSPayload_QnameTooLongDomain(t *testing.T) {
	cfg := dnsutils.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)
	chanTo := make(chan dnsutils.DNSMessage, 512)

	// prepare dnstap
	dnsQname := dnsutils.BadVeryLongDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-chanTo
	if !msg.DNS.MalformedPacket {
		t.Errorf("DNS message should malformed because of qname too long")
	}
}

func TestPowerDNS_Processor_AddDNSPayload_AnswersTooLongDomain(t *testing.T) {
	cfg := dnsutils.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)
	chanTo := make(chan dnsutils.DNSMessage, 512)

	// prepare dnstap
	dnsQname := dnsutils.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	rrQname := dnsutils.BadVeryLongDomain
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

	go consumer.Run([]chan dnsutils.DNSMessage{chanTo}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-chanTo

	// tests verifications
	if !msg.DNS.MalformedPacket {
		t.Errorf("DNS message is not malformed")
	}
}
