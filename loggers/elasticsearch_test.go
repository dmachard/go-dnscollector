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
)

func Test_ElasticSearchClient(t *testing.T) {

	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    dnsutils.MODE_FLATJSON,
			pattern: "\"dns.qname\":\"dns.collector\"",
		},
	}

	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:9200")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			conf := dnsutils.GetFakeConfig()
			g := NewElasticSearchClient(conf, logger.New(false), "test")

			go g.Run()

			dm := dnsutils.GetFakeDnsMessage()
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
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(payload)) {
				t.Errorf("loki test error want %s, got: %s", tc.pattern, string(payload))
			}
		})
	}
}
