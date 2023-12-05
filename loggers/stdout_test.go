package loggers

import (
	"bytes"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket/pcapgo"
)

func Test_StdoutTextMode(t *testing.T) {

	cfg := pkgconfig.GetFakeConfig()

	testcases := []struct {
		name      string
		delimiter string
		boundary  string
		qname     string
		expected  string
	}{
		{
			name:      "default_delimiter",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			qname:     "dns.collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 - - 0b dns.collector A -\n",
		},
		{
			name:      "custom_delimiter",
			delimiter: ";",
			boundary:  cfg.Global.TextFormatBoundary,
			qname:     "dns.collector",
			expected:  "-;collector;CLIENT_QUERY;NOERROR;1.2.3.4;1234;-;-;0b;dns.collector;A;-\n",
		},
		{
			name:      "default_boundary",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			qname:     "dns. collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 - - 0b \"dns. collector\" A -\n",
		},
		{
			name:      "custom_boundary",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  "!",
			qname:     "dns. collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 - - 0b !dns. collector! A -\n",
		},
		{
			name:      "boundary_in_qname",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			qname:     "d ns.\"collector\"",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 - - 0b \"d ns.\\\"collector\\\"\" A -\n",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// init logger and redirect stdout output to bytes buffer
			var stdout bytes.Buffer

			cfg := pkgconfig.GetFakeConfig()
			cfg.Global.TextFormatDelimiter = tc.delimiter
			cfg.Global.TextFormatBoundary = tc.boundary

			g := NewStdOut(cfg, logger.New(false), "test")
			g.SetTextWriter(&stdout)

			go g.Run()

			// print dns message to stdout buffer
			dm := dnsutils.GetFakeDNSMessage()
			dm.DNS.Qname = tc.qname
			g.Channel() <- dm

			// stop logger
			time.Sleep(time.Second)
			g.Stop()

			// check buffer
			if stdout.String() != tc.expected {
				t.Errorf("invalid stdout output: %s", stdout.String())
			}
		})
	}
}

func Test_StdoutJsonMode(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
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
			// init logger and redirect stdout output to bytes buffer
			var stdout bytes.Buffer

			cfg := pkgconfig.GetFakeConfig()
			cfg.Loggers.Stdout.Mode = tc.mode
			g := NewStdOut(cfg, logger.New(false), "test")
			g.SetTextWriter(&stdout)

			go g.Run()

			// print dns message to stdout buffer
			dm := dnsutils.GetFakeDNSMessage()
			g.Channel() <- dm

			// stop logger
			time.Sleep(time.Second)
			g.Stop()

			// check buffer
			pattern := regexp.MustCompile(tc.pattern)
			ret := stdout.String()
			if !pattern.MatchString(ret) {
				t.Errorf("stdout error want %s, got: %s", tc.pattern, ret)
			}
		})
	}
}

func Test_StdoutPcapMode(t *testing.T) {
	// redirect stdout output to bytes buffer
	var pcap bytes.Buffer

	// init logger and run
	cfg := pkgconfig.GetFakeConfig()
	cfg.Loggers.Stdout.Mode = "pcap"

	g := NewStdOut(cfg, logger.New(false), "test")
	g.SetPcapWriter(&pcap)

	go g.Run()

	// send DNSMessage to channel
	dm := dnsutils.GetFakeDNSMessageWithPayload()
	g.Channel() <- dm

	// stop logger
	time.Sleep(time.Second)
	g.Stop()

	// check pcap output
	pcapReader, err := pcapgo.NewReader(bytes.NewReader(pcap.Bytes()))
	if err != nil {
		t.Errorf("unable to read pcap: %s", err)
		return
	}
	data, _, err := pcapReader.ReadPacketData()
	if err != nil {
		t.Errorf("unable to read packet: %s", err)
		return
	}
	if len(data) < dm.DNS.Length {
		t.Errorf("incorrect packet size: %d", len(data))
	}
}

func Test_StdoutPcapMode_NoDNSPayload(t *testing.T) {
	// redirect stdout output to bytes buffer
	logger := logger.New(false)
	var logs bytes.Buffer
	logger.SetOutput(&logs)

	var pcap bytes.Buffer

	// init logger and run
	cfg := pkgconfig.GetFakeConfig()
	cfg.Loggers.Stdout.Mode = "pcap"

	g := NewStdOut(cfg, logger, "test")
	g.SetPcapWriter(&pcap)

	go g.Run()

	// send DNSMessage to channel
	dm := dnsutils.GetFakeDNSMessage()
	g.Channel() <- dm

	// stop logger
	time.Sleep(time.Second)
	g.Stop()

	// check output
	regxp := "ERROR:.*process: no dns payload to encode, drop it.*"
	pattern := regexp.MustCompile(regxp)
	ret := logs.String()
	if !pattern.MatchString(ret) {
		t.Errorf("stdout error want %s, got: %s", regxp, ret)
	}
}
