package workers

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
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
			mode:    config.ModeText,
			pattern: "0b dns.collector A",
		},
		{
			mode:    config.ModeJSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    config.ModeFlatJSON,
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
			cfg := config.GetDefaultConfig()
			cfg.Loggers.LokiClient.Mode = tc.mode
			cfg.Loggers.LokiClient.BatchSize = 0
			g := NewLokiClient(cfg, logger.New(false), "test")

			// start the logger
			go g.StartCollect()
			defer g.Stop()

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			dm.DNSTap.Identity = dnsutils.DNSTapIdentityTest
			g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

			// accept conn
			conn, err := fakeRcvr.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			// read and parse http request on server side
			request, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte(config.HTTPOK))

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
		name          string
		relabelConfig []*relabel.Config
		labelsPattern string
	}{
		{
			name: "export rcode label from __dns_rcode",
			relabelConfig: []*relabel.Config{
				{
					Action:       relabel.Replace,
					Separator:    ";",
					Regex:        relabel.MustNewRegexp("^(.+)$"),
					Replacement:  "$1",
					SourceLabels: model.LabelNames{"__dns_rcode"},
					TargetLabel:  "rcode",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\", rcode=\"NOERROR\"}",
		},
		{
			name: "internal relabel is dropped (__ labels are not exported)",
			relabelConfig: []*relabel.Config{
				{
					Action:       relabel.Replace,
					Separator:    ";",
					Regex:        relabel.MustNewRegexp("^(.+)$"),
					Replacement:  "$1",
					SourceLabels: model.LabelNames{"__dns_rcode"},
					TargetLabel:  "__rcode",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\"}",
		},
		{
			name: "drop job label via relabel config",
			relabelConfig: []*relabel.Config{
				{
					Action: relabel.LabelDrop,
					Regex:  relabel.MustNewRegexp("job"),
				},
			},
			labelsPattern: "{identity=\"test_id\"}",
		},
		{
			name: "labelmap reads every internal label",
			relabelConfig: []*relabel.Config{
				{
					Action:      relabel.LabelMap,
					Regex:       relabel.MustNewRegexp("__dns_(rcode)"),
					Replacement: "$1",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\", rcode=\"NOERROR\"}",
		},
		{
			name: "keepequal reads its target label",
			relabelConfig: []*relabel.Config{
				{
					Action:      relabel.Replace,
					Regex:       relabel.MustNewRegexp("(.*)"),
					Replacement: "NOERROR",
					TargetLabel: "__want",
				},
				{
					Action:       relabel.KeepEqual,
					SourceLabels: model.LabelNames{"__want"},
					TargetLabel:  "__dns_rcode",
				},
				{
					Action:      relabel.Replace,
					Regex:       relabel.MustNewRegexp("(.*)"),
					Replacement: "kept",
					TargetLabel: "status",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\", status=\"kept\"}",
		},
	}

	// fake msgpack receiver
	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:3100")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		for _, m := range []string{config.ModeText, config.ModeJSON, config.ModeFlatJSON} {
			t.Run(fmt.Sprintf("%s/%s", m, tc.name), func(t *testing.T) {
				// init logger
				cfg := config.GetDefaultConfig()
				cfg.Loggers.LokiClient.Mode = m
				cfg.Loggers.LokiClient.BatchSize = 0
				cfg.Loggers.LokiClient.RelabelConfigs = tc.relabelConfig
				g := NewLokiClient(cfg, logger.New(true), "test")

				// start the logger
				go g.StartCollect()
				defer g.Stop()

				// send fake dns message to logger
				dm := dnsutils.GetFakeDNSMessage()
				dm.DNSTap.Identity = dnsutils.DNSTapIdentityTest
				g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

				// accept conn; a message the relabel rules dropped never arrives
				_ = fakeRcvr.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
				conn, err := fakeRcvr.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()

				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

				// read and parse http request on server side
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					t.Fatal(err)
				}
				conn.Write([]byte(config.HTTPOK))

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

func Test_LokiClientRelabelInput(t *testing.T) {
	flat := map[string]interface{}{
		"dns.qname":             "dns.collector",
		"dns.rcode":             "NOERROR",
		"dnstap.identity":       "test_id",
		"network-info.query-ip": "1.2.3.4",
	}

	testcases := []struct {
		name   string
		rules  []*relabel.Config
		expect []string
	}{
		{
			name: "only the source labels are built",
			rules: []*relabel.Config{
				{Action: relabel.Replace, Regex: relabel.MustNewRegexp("(.*)"), Replacement: "$1",
					SourceLabels: model.LabelNames{"__dns_qname"}, TargetLabel: "qname"},
				{Action: relabel.Keep, Regex: relabel.MustNewRegexp("1.*"),
					SourceLabels: model.LabelNames{"__network_info_query_ip"}},
			},
			expect: []string{"__dns_qname", "__network_info_query_ip"},
		},
		{
			name: "keepequal target is built",
			rules: []*relabel.Config{
				{Action: relabel.KeepEqual, SourceLabels: model.LabelNames{"__dns_qname"}, TargetLabel: "__dns_rcode"},
			},
			expect: []string{"__dns_qname", "__dns_rcode"},
		},
		{
			name: "labelmap builds everything",
			rules: []*relabel.Config{
				{Action: relabel.LabelMap, Regex: relabel.MustNewRegexp("__dns_(.*)"), Replacement: "$1"},
			},
			expect: []string{"__dns_qname", "__dns_rcode", "__dnstap_identity", "__network_info_query_ip"},
		},
		{
			name:   "no source labels builds nothing",
			rules:  []*relabel.Config{{Action: relabel.LabelDrop, Regex: relabel.MustNewRegexp("job")}},
			expect: []string{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.GetDefaultConfig()
			cfg.Loggers.LokiClient.RelabelConfigs = tc.rules
			g := NewLokiClient(cfg, logger.New(false), "test")

			got := []string{}
			for _, l := range g.relabelInput(flat, nil) {
				got = append(got, l.Name)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(tc.expect, ",") {
				t.Errorf("want %v, got %v", tc.expect, got)
			}
			for _, rc := range tc.rules {
				if rc.NameValidationScheme != model.LegacyValidation {
					t.Errorf("validation scheme not set on %v", rc.Action)
				}
			}
		})
	}
}

// Test_LokiClient_SlowSinkDrops reproduces discussion #1392.
//
// Topology:
//
//	burst sender → LokiClient.inputChannel → StartCollect → outputChannel
//	                                                       → StartLogging → SendEntries → slow HTTP
//
// When SendEntries blocks on a slow HTTP server, StartLogging cannot drain
// the outputChannel, which causes StartCollect to block on its send, which
// causes the inputChannel to fill up. Senders then drop with WorkerIsBusy.
//
// This test verifies the saturation directly: after a burst with a slow
// Loki server, the inputChannel must be at capacity (len == cap).
// After the fix (async SendEntries), this assertion should be inverted.
func Test_LokiClient_SlowSinkDrops(t *testing.T) {
	const (
		lokiSlowDelay = 200 * time.Millisecond
		lokiChanSize  = 8
		lokiBurstSize = 64 // >> lokiChanSize so we guarantee saturation
	)

	// fake slow Loki server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var httpHits atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				time.Sleep(lokiSlowDelay) // simulate slow Loki
				c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
				httpHits.Add(1)
			}(conn)
		}
	}()

	cfg := config.GetDefaultConfig()
	cfg.Loggers.LokiClient.ServerURL = "http://" + ln.Addr().String() + "/loki/api/v1/push"
	cfg.Loggers.LokiClient.BatchSize = 0 // flush on every message
	cfg.Global.Worker.ChannelBufferSize = lokiChanSize

	w := NewLokiClient(cfg, logger.New(false), "test-slow-loki")
	go w.StartCollect()
	defer func() {
		// drain the input channel so Stop() can complete without deadlock
		go func() {
			for range w.GetInputChannel() {
			}
		}()
		w.Stop()
	}()

	// give worker goroutines a moment to start
	time.Sleep(20 * time.Millisecond)

	// send first batch so StartLogging calls SendEntries and blocks there
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNSTap.Identity = "test"
	w.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	// give StartLogging time to pick it up and block inside SendEntries
	time.Sleep(50 * time.Millisecond)

	// now flood the input channel — it should fill up because
	// StartCollect is blocked trying to send to the full outputChannel
	var dropped int
	for i := 0; i < lokiBurstSize; i++ {
		time.Sleep(100 * time.Microsecond)
		select {
		case w.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm):
		default:
			dropped++
		}
	}

	// give workers a moment to drain the burst
	time.Sleep(20 * time.Millisecond)

	chanLen := len(w.GetInputChannel())
	chanCap := cap(w.GetInputChannel())

	t.Logf("inputChannel: len=%d cap=%d  dropped=%d  Loki hits=%d",
		chanLen, chanCap, dropped, httpHits.Load())

	// With buffered async sending, StartLogging is not blocked in SendEntries
	// and drains the channels even when Loki server is slow: zero drops and drained channel.
	if dropped > 0 {
		t.Errorf("expected 0 dropped messages with async buffered sending, got %d dropped", dropped)
	}
	if chanLen >= chanCap {
		t.Errorf(
			"expected inputChannel to be drained (len=%d should be < cap=%d); "+
				"worker still blocked on slow sink",
			chanLen, chanCap,
		)
	}
}
