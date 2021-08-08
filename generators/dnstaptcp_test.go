package generators

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func TestDnstapTcpRun(t *testing.T) {
	// init generator
	g := NewDnstapTcpSender(dnsutils.GetFakeConfig(), logger.New(false))

	// fake dnstap receiver
	fakeRcvr, err := net.Listen("tcp", ":6000")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the generator
	go g.Run()

	// accept conn from generator
	conn, err := fakeRcvr.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// init framestream on server side
	fs_svr := framestream.NewFstrm(bufio.NewReader(conn), bufio.NewWriter(conn), conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
	if err := fs_svr.InitReceiver(); err != nil {
		t.Errorf("error to init framestream receiver: %s", err)
	}

	// send fake dns message to generator
	dm := dnsutils.GetFakeDnsMessage()
	g.channel <- dm

	// receive frame on server side ?, timeout 5s
	fs, err := fs_svr.RecvFrame(true)
	if err != nil {
		t.Errorf("error to receive frame: %s", err)
	}

	// decode the dnstap message in server side
	dt := &dnstap.Dnstap{}
	if err := proto.Unmarshal(fs.Data(), dt); err != nil {
		t.Errorf("error to decode dnstap")
	}
}
