package loggers

import (
	"bufio"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func Test_TcpClientRun(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    dnsutils.ModeText,
			pattern: " dns.collector ",
		},
		{
			mode:    dnsutils.ModeJSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    dnsutils.ModeFlatJSON,
			pattern: "\"dns.qname\":\"dns.collector\"",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			cfg := dnsutils.GetFakeConfig()
			cfg.Loggers.TCPClient.FlushInterval = 1
			cfg.Loggers.TCPClient.BufferSize = 0
			cfg.Loggers.TCPClient.Mode = tc.mode
			cfg.Loggers.TCPClient.RemoteAddress = "127.0.0.1"
			cfg.Loggers.TCPClient.RemotePort = 9999

			g := NewTCPClient(cfg, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(dnsutils.SocketTCP, ":9999")
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

			// wait connection on logger
			time.Sleep(time.Second)

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			g.Channel() <- dm

			// read data on server side and decode-it
			reader := bufio.NewReader(conn)
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(line) {
				t.Errorf("tcp error want %s, got: %s", tc.pattern, line)
			}

			// stop all
			fakeRcvr.Close()
			g.Stop()
		})
	}
}
