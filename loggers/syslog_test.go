package loggers

import (
	"bufio"
	"net"
	"regexp"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func Test_SyslogRun(t *testing.T) {
	testcases := []struct {
		transport string
		mode      string
		pattern   string
	}{
		{
			transport: dnsutils.SOCKET_TCP,
			mode:      dnsutils.MODE_TEXT,
			pattern:   " dns.collector ",
		},
		{
			transport: dnsutils.SOCKET_TCP,
			mode:      dnsutils.MODE_JSON,
			pattern:   "\"qname\":\"dns.collector\"",
		},
		{
			transport: dnsutils.SOCKET_TCP,
			mode:      dnsutils.MODE_FLATJSON,
			pattern:   "\"dns.qname\":\"dns.collector\"",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			config := dnsutils.GetFakeConfig()
			config.Loggers.Syslog.Transport = tc.transport
			config.Loggers.Syslog.RemoteAddress = ":4000"
			config.Loggers.Syslog.Mode = tc.mode
			g := NewSyslog(config, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(tc.transport, ":4000")
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
			dm := dnsutils.GetFakeDnsMessage()
			g.channel <- dm

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
