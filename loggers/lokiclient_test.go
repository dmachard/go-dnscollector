package loggers

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/golang/snappy"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
)

func Test_LokiClientRun(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    pkgconfig.ModeText,
			pattern: "0b dns.collector A",
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

	// fake msgpack receiver
	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:3100")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			cfg := pkgconfig.GetFakeConfig()
			cfg.Loggers.LokiClient.Mode = tc.mode
			cfg.Loggers.LokiClient.BatchSize = 0
			g := NewLokiClient(cfg, logger.New(false), "test")

			// start the logger
			go g.Run()

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			dm.DNSTap.Identity = pkgconfig.DNSTapIdentityTest
			g.Channel() <- dm

			// accept conn
			conn, err := fakeRcvr.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			// read and parse http request on server side
			request, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte(pkgconfig.HTTPOK))

			// read payload from request body
			protobuf, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}

			protobufDec, err := snappy.Decode(nil, protobuf)
			if err != nil {
				t.Fatal(err)
			}
			labelsPattern := regexp.MustCompile("{identity=\"test_id\", job=\"dnscollector\"}")
			if !labelsPattern.MatchString(string(protobufDec)) {
				t.Errorf("loki test error want {identity=\"test_id\", job=\"dnscollector\"}, got: %s", string(protobufDec))
			}
			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(protobufDec)) {
				t.Errorf("loki test error want %s, got: %s", tc.pattern, string(protobufDec))
			}
		})
	}
}

func Test_LokiClientRelabel(t *testing.T) {
	testcases := []struct {
		relabelConfig []*relabel.Config
		labelsPattern string
	}{
		{
			relabelConfig: []*relabel.Config{
				{
					Action:       relabel.Replace,
					Separator:    ";",
					Regex:        relabel.MustNewRegexp("(.*)"),
					Replacement:  "$1",
					SourceLabels: model.LabelNames{"__dns_rcode"},
					TargetLabel:  "rcode",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\", rcode=\"NOERROR\"}",
		},
		{
			relabelConfig: []*relabel.Config{
				{
					Action:       relabel.Replace,
					Separator:    ";",
					Regex:        relabel.MustNewRegexp("(.*)"),
					Replacement:  "$1",
					SourceLabels: model.LabelNames{"__dns_rcode"},
					TargetLabel:  "__rcode",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\"}",
		},
		{
			relabelConfig: []*relabel.Config{
				{
					Action: relabel.LabelDrop,
					Regex:  relabel.MustNewRegexp("job"),
				},
			},
			labelsPattern: "{identity=\"test_id\"}",
		},
	}

	// fake msgpack receiver
	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:3100")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		for _, m := range []string{pkgconfig.ModeText, pkgconfig.ModeJSON, pkgconfig.ModeFlatJSON} {
			t.Run(fmt.Sprint(m, tc.relabelConfig, tc.labelsPattern), func(t *testing.T) {
				// init logger
				cfg := pkgconfig.GetFakeConfig()
				cfg.Loggers.LokiClient.Mode = m
				cfg.Loggers.LokiClient.BatchSize = 0
				cfg.Loggers.LokiClient.RelabelConfigs = tc.relabelConfig
				g := NewLokiClient(cfg, logger.New(false), "test")

				// start the logger
				go g.Run()

				// send fake dns message to logger
				dm := dnsutils.GetFakeDNSMessage()
				dm.DNSTap.Identity = pkgconfig.DNSTapIdentityTest
				g.Channel() <- dm

				// accept conn
				conn, err := fakeRcvr.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()

				// read and parse http request on server side
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					t.Fatal(err)
				}
				conn.Write([]byte(pkgconfig.HTTPOK))

				// read payload from request body
				protobuf, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}

				protobufDec, err := snappy.Decode(nil, protobuf)
				if err != nil {
					t.Fatal(err)
				}

				labelsPattern := regexp.MustCompile(tc.labelsPattern)
				if !labelsPattern.MatchString(string(protobufDec)) {
					t.Errorf("loki test error want %s, got: %s", tc.labelsPattern, string(protobufDec))
				}
			})
		}
	}
}
