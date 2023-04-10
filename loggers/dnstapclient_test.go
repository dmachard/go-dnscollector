package loggers

import (
	"bufio"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func Test_DnstapClientTcpRun(t *testing.T) {
	// init logger
	cfg := dnsutils.GetFakeConfig()
	cfg.Loggers.Dnstap.FlushInterval = 1
	cfg.Loggers.Dnstap.BufferSize = 1

	g := NewDnstapSender(cfg, logger.New(false), "test")

	// fake dnstap receiver
	fakeRcvr, err := net.Listen("tcp", ":6000")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.Run()

	// accept conn from logger
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

	// send fake dns message to logger
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

func Test_DnstapClientUnixRun(t *testing.T) {

	sockAddr := "/tmp/test.sock"

	// init logger
	config := dnsutils.GetFakeConfig()
	config.Loggers.Dnstap.SockPath = sockAddr
	config.Loggers.Dnstap.FlushInterval = 1
	config.Loggers.Dnstap.BufferSize = 1
	g := NewDnstapSender(config, logger.New(false), "test")

	// fake dnstap receiver
	if err := os.RemoveAll(sockAddr); err != nil {
		log.Fatal(err)
	}
	fakeRcvr, err := net.Listen("unix", sockAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.Run()

	// accept conn from logger
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

	// send fake dns message to logger
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
