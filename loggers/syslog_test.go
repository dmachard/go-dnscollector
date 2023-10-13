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

func Test_SyslogRun(t *testing.T) {
	testcases := []struct {
		transport  string
		mode       string
		pattern    string
		listenAddr string
	}{
		{
			transport:  dnsutils.SOCKET_TCP,
			mode:       dnsutils.MODE_TEXT,
			pattern:    " dns.collector ",
			listenAddr: ":4000",
		},
		{
			transport:  dnsutils.SOCKET_TCP,
			mode:       dnsutils.MODE_JSON,
			pattern:    "\"qname\":\"dns.collector\"",
			listenAddr: ":4001",
		},
		{
			transport:  dnsutils.SOCKET_TCP,
			mode:       dnsutils.MODE_FLATJSON,
			pattern:    "\"dns.qname\":\"dns.collector\"",
			listenAddr: ":4002",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			config := dnsutils.GetFakeConfig()
			config.Loggers.Syslog.Transport = tc.transport
			config.Loggers.Syslog.RemoteAddress = tc.listenAddr
			config.Loggers.Syslog.Mode = tc.mode
			config.Loggers.Syslog.Format = "unix"

			g := NewSyslog(config, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(tc.transport, tc.listenAddr)
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

			// send fake dns message to logger
			time.Sleep(time.Second)
			dm := dnsutils.GetFakeDnsMessage()
			g.Channel() <- dm

			// read data on server side and decode-it
			reader := bufio.NewReader(conn)
			line, _, err := reader.ReadLine()
			if err != nil {
				t.Errorf("error to read line on syslog server: %s", err)
			}
			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(line)) {
				t.Errorf("syslog error want %s, got: %s", tc.pattern, string(line))
			}
		})
	}
}
