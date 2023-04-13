package loggers

import (
	"bytes"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func Test_StdoutTextMode(t *testing.T) {

	cfg := dnsutils.GetFakeConfig()

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

			cfg := dnsutils.GetFakeConfig()
			cfg.Global.TextFormatDelimiter = tc.delimiter
			cfg.Global.TextFormatBoundary = tc.boundary

			g := NewStdOut(cfg, logger.New(false), "test")
			g.SetBuffer(&stdout)

			go g.Run()

			// print dns message to stdout buffer
			dm := dnsutils.GetFakeDnsMessage()
			dm.DNS.Qname = tc.qname
			g.channel <- dm

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
			mode:    dnsutils.MODE_JSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    dnsutils.MODE_FLATJSON,
			pattern: "\"dns.qname\":\"dns.collector\"",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger and redirect stdout output to bytes buffer
			var stdout bytes.Buffer

			cfg := dnsutils.GetFakeConfig()
			cfg.Loggers.Stdout.Mode = tc.mode
			g := NewStdOut(cfg, logger.New(false), "test")
			g.SetBuffer(&stdout)

			go g.Run()

			// print dns message to stdout buffer
			dm := dnsutils.GetFakeDnsMessage()
			g.channel <- dm

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
