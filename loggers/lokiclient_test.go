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
			mode:    dnsutils.MODE_TEXT,
			pattern: "0b dns.collector A",
		},
		{
			mode:    dnsutils.MODE_JSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    dnsutils.MODE_FLATJSON,
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
			cfg := dnsutils.GetFakeConfig()
			cfg.Loggers.LokiClient.Mode = tc.mode
			cfg.Loggers.LokiClient.BatchSize = 0
			g := NewLokiClient(cfg, logger.New(false), "test")

			// start the logger
			go g.Run()

			// send fake dns message to logger
			dm := dnsutils.GetFakeDnsMessage()
			dm.DnsTap.Identity = dnsutils.DNSTAP_IDENTITY_TEST
			g.channel <- dm

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
			conn.Write([]byte(dnsutils.HTTP_OK))

			// read payload from request body
			protobuf, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}

			protobuf_dec, err := snappy.Decode(nil, protobuf)
			if err != nil {
				t.Fatal(err)
			}
			labels_pattern := regexp.MustCompile("{identity=\"test_id\", job=\"dnscollector\"}")
			if !labels_pattern.MatchString(string(protobuf_dec)) {
				t.Errorf("loki test error want {identity=\"test_id\", job=\"dnscollector\"}, got: %s", string(protobuf_dec))
			}
			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(protobuf_dec)) {
				t.Errorf("loki test error want %s, got: %s", tc.pattern, string(protobuf_dec))
			}
		})
	}
}

func Test_LokiClientRelabel(t *testing.T) {
	testcases := []struct {
		relabel_config []*relabel.Config
		labels_pattern string
	}{
		{
			relabel_config: []*relabel.Config{
				{
					Action:       relabel.Replace,
					Separator:    ";",
					Regex:        relabel.MustNewRegexp("(.*)"),
					Replacement:  "$1",
					SourceLabels: model.LabelNames{"__dns_rcode"},
					TargetLabel:  "rcode",
				},
			},
			labels_pattern: "{identity=\"test_id\", job=\"dnscollector\", rcode=\"NOERROR\"}",
		},
		{
			relabel_config: []*relabel.Config{
				{
					Action:       relabel.Replace,
					Separator:    ";",
					Regex:        relabel.MustNewRegexp("(.*)"),
					Replacement:  "$1",
					SourceLabels: model.LabelNames{"__dns_rcode"},
					TargetLabel:  "__rcode",
				},
			},
			labels_pattern: "{identity=\"test_id\", job=\"dnscollector\"}",
		},
		{
			relabel_config: []*relabel.Config{
				{
					Action: relabel.LabelDrop,
					Regex:  relabel.MustNewRegexp("job"),
				},
			},
			labels_pattern: "{identity=\"test_id\"}",
		},
	}

	// fake msgpack receiver
	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:3100")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		for _, m := range []string{dnsutils.MODE_TEXT, dnsutils.MODE_JSON, dnsutils.MODE_FLATJSON} {
			t.Run(fmt.Sprint(m, tc.relabel_config, tc.labels_pattern), func(t *testing.T) {
				// init logger
				cfg := dnsutils.GetFakeConfig()
				cfg.Loggers.LokiClient.Mode = m
				cfg.Loggers.LokiClient.BatchSize = 0
				cfg.Loggers.LokiClient.RelabelConfigs = tc.relabel_config
				g := NewLokiClient(cfg, logger.New(false), "test")

				// start the logger
				go g.Run()

				// send fake dns message to logger
				dm := dnsutils.GetFakeDnsMessage()
				dm.DnsTap.Identity = dnsutils.DNSTAP_IDENTITY_TEST
				g.channel <- dm

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
				conn.Write([]byte(dnsutils.HTTP_OK))

				// read payload from request body
				protobuf, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}

				protobuf_dec, err := snappy.Decode(nil, protobuf)
				if err != nil {
					t.Fatal(err)
				}

				labels_pattern := regexp.MustCompile(tc.labels_pattern)
				if !labels_pattern.MatchString(string(protobuf_dec)) {
					t.Errorf("loki test error want %s, got: %s", tc.labels_pattern, string(protobuf_dec))
				}
			})
		}
	}
}
