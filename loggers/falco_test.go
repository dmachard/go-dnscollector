package loggers

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"regexp"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_FalcoClient(t *testing.T) {

	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    pkgconfig.ModeJSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
	}

	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:9200")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			conf := pkgconfig.GetFakeConfig()
			g := NewFalcoClient(conf, logger.New(false), "test")

			go g.StartCollect()

			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dm

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
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(payload)) {
				t.Errorf("falco test error want %s, got: %s", tc.pattern, string(payload))
			}
		})
	}
}
