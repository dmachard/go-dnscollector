package workers

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

func Test_SyslogRunUdp(t *testing.T) {
	testcases := []struct {
		name       string
		transport  string
		mode       string
		formatter  string
		framer     string
		pattern    string
		listenAddr string
	}{
		{
			name:       "unix_format",
			transport:  netutils.SocketUDP,
			mode:       pkgconfig.ModeText,
			formatter:  netutils.SocketUnix,
			framer:     "",
			pattern:    `<30>\D+ \d+ \d+:\d+:\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc3164_format",
			transport:  netutils.SocketUDP,
			mode:       pkgconfig.ModeText,
			formatter:  "rfc3164",
			framer:     "",
			pattern:    `<30>\D+ \d+ \d+:\d+:\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc5424_format",
			transport:  netutils.SocketUDP,
			mode:       pkgconfig.ModeText,
			formatter:  "rfc5424",
			framer:     "",
			pattern:    `<30>1 \d+-\d+-\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc5424_format_rfc5425_framer",
			transport:  netutils.SocketUDP,
			mode:       pkgconfig.ModeText,
			formatter:  "rfc5424",
			framer:     "rfc5425",
			pattern:    `\d+ \<30\>1 \d+-\d+-\d+.*`,
			listenAddr: ":4000",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// init logger
			config := pkgconfig.GetDefaultConfig()
			config.Loggers.Syslog.Transport = tc.transport
			config.Loggers.Syslog.RemoteAddress = tc.listenAddr
			config.Loggers.Syslog.Mode = tc.mode
			config.Loggers.Syslog.Formatter = tc.formatter
			config.Loggers.Syslog.Framer = tc.framer
			config.Loggers.Syslog.FlushInterval = 1
			config.Loggers.Syslog.BufferSize = 0

			g := NewSyslog(config, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.ListenPacket(tc.transport, tc.listenAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer fakeRcvr.Close()

			// start the logger
			go g.StartCollect()

			// send fake dns message to logger
			time.Sleep(time.Second)
			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dm

			// read data on fake server side
			buf := make([]byte, 4096)
			n, _, err := fakeRcvr.ReadFrom(buf)
			if err != nil {
				t.Errorf("error to read data: %s", err)
			}

			if n == 0 {
				t.Errorf("no data received")
			}

			re := regexp.MustCompile(tc.pattern)
			if !re.MatchString(string(buf)) {
				t.Errorf("syslog error want %s, got: %s", tc.pattern, string(buf))
			}
		})
	}
}

func Test_SyslogRunTcp(t *testing.T) {
	testcases := []struct {
		name       string
		transport  string
		mode       string
		formatter  string
		framer     string
		pattern    string
		listenAddr string
	}{
		{
			name:       "unix_format",
			transport:  netutils.SocketTCP,
			mode:       pkgconfig.ModeText,
			formatter:  netutils.SocketUnix,
			framer:     "",
			pattern:    `<30>\D+ \d+ \d+:\d+:\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc3164_format",
			transport:  netutils.SocketTCP,
			mode:       pkgconfig.ModeText,
			formatter:  "rfc3164",
			framer:     "",
			pattern:    `<30>\D+ \d+ \d+:\d+:\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc5424_format",
			transport:  netutils.SocketTCP,
			mode:       pkgconfig.ModeText,
			formatter:  "rfc5424",
			framer:     "",
			pattern:    `<30>1 \d+-\d+-\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc5425_format_rfc5425_framer",
			transport:  netutils.SocketTCP,
			mode:       pkgconfig.ModeText,
			formatter:  "rfc5424",
			framer:     "rfc5425",
			pattern:    `\d+ \<30\>1 \d+-\d+-\d+.*`,
			listenAddr: ":4000",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// init logger
			config := pkgconfig.GetDefaultConfig()
			config.Loggers.Syslog.Transport = tc.transport
			config.Loggers.Syslog.RemoteAddress = tc.listenAddr
			config.Loggers.Syslog.Mode = tc.mode
			config.Loggers.Syslog.Formatter = tc.formatter
			config.Loggers.Syslog.Framer = tc.framer
			config.Loggers.Syslog.FlushInterval = 1
			config.Loggers.Syslog.BufferSize = 0

			g := NewSyslog(config, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(tc.transport, tc.listenAddr)
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

			// send fake dns message to logger
			time.Sleep(time.Second)
			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dm

			// read data on server side and decode-it
			reader := bufio.NewReader(conn)
			line, _, err := reader.ReadLine()
			if err != nil {
				t.Errorf("error to read line on syslog server: %s", err)
			}

			re := regexp.MustCompile(tc.pattern)
			if !re.MatchString(string(line)) {
				t.Errorf("syslog error want %s, got: %s", tc.pattern, string(line))
			}
		})
	}
}

func Test_SyslogRun_RemoveNullCharacter(t *testing.T) {
	// init logger
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.Syslog.Transport = netutils.SocketUDP
	config.Loggers.Syslog.RemoteAddress = ":4000"
	config.Loggers.Syslog.Mode = pkgconfig.ModeText
	config.Loggers.Syslog.Formatter = netutils.SocketUnix
	config.Loggers.Syslog.Framer = ""
	config.Loggers.Syslog.FlushInterval = 1
	config.Loggers.Syslog.BufferSize = 0

	g := NewSyslog(config, logger.New(false), "test")

	// fake json receiver
	fakeRcvr, err := net.ListenPacket(config.Loggers.Syslog.Transport, ":4000")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.StartCollect()

	// send fake dns message to logger
	time.Sleep(time.Second)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "null\x00char.com"
	g.GetInputChannel() <- dm

	// read data on fake server side
	buf := make([]byte, (500))

	n, _, err := fakeRcvr.ReadFrom(buf)
	if err != nil {
		t.Errorf("error to read data: %s", err)
	}

	if n == 0 {
		t.Errorf("no data received")
	}

	// search null char
	for _, b := range buf[:n] {
		if b == '\x00' {
			t.Errorf("NULL char detected in log")
		}
	}

	// search qname
	pattern := `null` + config.Loggers.Syslog.ReplaceNullChar + `char\.com`
	re := regexp.MustCompile(pattern)
	if !re.MatchString(string(buf[:n])) {
		t.Errorf("syslog error want %s, got: %s", pattern, string(buf[:n]))
	}
}
