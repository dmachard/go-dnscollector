package collectors

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"google.golang.org/protobuf/proto"
)

func TestPowerDNS_Processor(t *testing.T) {
	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, dnsutils.GetFakeConfig(), logger.New(false), "test", 512)
	chan_to := make(chan dnsutils.DnsMessage, 512)

	// prepare dnstap
	dnsQname := "test."
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	go consumer.Run([]chan dnsutils.DnsMessage{chan_to}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-chan_to
	if msg.DnsTap.Identity != "powerdnspb" {
		t.Errorf("invalid identity in dns message: %s", msg.DnsTap.Identity)
	}
}

func TestPowerDNS_Processor_InvalidLabelLength(t *testing.T) {
	cfg := dnsutils.GetFakeConfig()
	cfg.Collectors.PowerDNS.AddDnsPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, cfg, logger.New(false), "test", 512)
	chan_to := make(chan dnsutils.DnsMessage, 512)

	// prepare dnstap
	dnsQname := "ultramegaverytoolonglabel-ultramegaverytoolonglabel-ultramegaverytoolonglabel.dnscollector.dev."
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	go consumer.Run([]chan dnsutils.DnsMessage{chan_to}, []string{"test"})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-chan_to
	if !msg.DNS.MalformedPacket {
		t.Errorf("DNS message should malformed")
	}
}
