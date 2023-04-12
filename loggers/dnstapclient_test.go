package loggers

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

func Test_DnstapClient(t *testing.T) {

	testcases := []struct {
		transport string
		address   string
	}{
		{
			transport: "tcp",
			address:   ":6000",
		},
		{
			transport: "unix",
			address:   "/tmp/test.sock",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.transport, func(t *testing.T) {
			// init logger
			cfg := dnsutils.GetFakeConfig()
			cfg.Loggers.Dnstap.FlushInterval = 1
			cfg.Loggers.Dnstap.BufferSize = 0
			if tc.transport == "unix" {
				cfg.Loggers.Dnstap.SockPath = tc.address
			}

			g := NewDnstapSender(cfg, logger.New(false), "test")

			// fake dnstap receiver
			fakeRcvr, err := net.Listen(tc.transport, tc.address)
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

			// wait framestream to be ready
			time.Sleep(time.Second)

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
		})
	}
}
