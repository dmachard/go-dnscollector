package collectors

import (
	"bytes"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"google.golang.org/protobuf/proto"
)

func Test_PdnsProcessor(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	consumer := NewPdnsProcessor(dnsutils.GetFakeConfig(), logger, "test")
	chan_to := make(chan dnsutils.DnsMessage, 512)

	// prepare dnstap
	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()

	data, _ := proto.Marshal(dm)

	go consumer.Run([]chan dnsutils.DnsMessage{chan_to})
	// add packet to consumer
	consumer.GetChannel() <- data

	// read dns message from dnstap consumer
	msg := <-chan_to
	if msg.DnsTap.Identity != "powerdnspb" {
		t.Errorf("invalid identity in dns message: %s", msg.DnsTap.Identity)
	}
}
