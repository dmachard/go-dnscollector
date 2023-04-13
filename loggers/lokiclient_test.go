package loggers

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"regexp"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/golang/snappy"
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
			dm.DnsTap.Identity = "test_id"
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

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(protobuf_dec)) {
				t.Errorf("loki test error want %s, got: %s", tc.pattern, string(protobuf_dec))
			}
		})
	}
}
