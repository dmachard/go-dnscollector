package loggers

import (
	"bufio"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_TcpClientRun(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    pkgconfig.ModeText,
			pattern: " dns.collector ",
		},
		{
			mode:    pkgconfig.ModeJSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    pkgconfig.ModeFlatJSON,
			pattern: "\"dns.qname\":\"dns.collector\"",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			cfg := pkgconfig.GetFakeConfig()
			cfg.Loggers.TCPClient.FlushInterval = 1
			cfg.Loggers.TCPClient.BufferSize = 0
			cfg.Loggers.TCPClient.Mode = tc.mode
			cfg.Loggers.TCPClient.RemoteAddress = "127.0.0.1"
			cfg.Loggers.TCPClient.RemotePort = 9999

			g := NewTCPClient(cfg, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(netutils.SocketTCP, ":9999")
			if err != nil {
				t.Fatal(err)
			}
			defer fakeRcvr.Close()

			// start the logger
			go g.StartCollect()

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
			g.GetInputChannel() <- dm

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

func Test_TcpClient_ConnectionAttempt(t *testing.T) {
	// init logger
	cfg := pkgconfig.GetFakeConfig()
	cfg.Loggers.TCPClient.FlushInterval = 1
	cfg.Loggers.TCPClient.Mode = pkgconfig.ModeText
	cfg.Loggers.TCPClient.RemoteAddress = "127.0.0.1"
	cfg.Loggers.TCPClient.RemotePort = 9999
	cfg.Loggers.TCPClient.ConnectTimeout = 1
	cfg.Loggers.TCPClient.RetryInterval = 2

	g := NewTCPClient(cfg, logger.New(true), "test")

	// start the logger
	go g.StartCollect()

	// just way to get connect attempt
	time.Sleep(time.Second * 3)

	// start receiver
	fakeRcvr, err := net.Listen(netutils.SocketTCP, ":9999")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

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
	g.GetInputChannel() <- dm

	// read data on server side and decode-it
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}

	pattern := regexp.MustCompile("dns.collector")
	if !pattern.MatchString(line) {
		t.Errorf("tcp error want dns.collector, got: %s", line)
	}

	// stop all
	fakeRcvr.Close()
	g.Stop()

}
