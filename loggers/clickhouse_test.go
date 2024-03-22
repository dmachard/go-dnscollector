package loggers

import (
	"bufio"
	"net"
	"net/http"
	"regexp"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_ClickhouseClient(t *testing.T) {

	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    pkgconfig.ModeJSON,
			pattern: "dns.collector",
		},
	}
	cfg := pkgconfig.GetFakeConfig()
	cfg.Loggers.ClickhouseClient.URL = "http://127.0.0.1:8123"
	cfg.Loggers.ClickhouseClient.User = "default"
	cfg.Loggers.ClickhouseClient.Password = "password"
	cfg.Loggers.ClickhouseClient.Database = "database"
	cfg.Loggers.ClickhouseClient.Table = "table"
	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:8123")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			g := NewClickhouseClient(cfg, logger.New(false), "test")

			go g.Run()

			dm := dnsutils.GetFakeDNSMessage()
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
			query := request.URL.Query().Get("query")
			conn.Write([]byte(pkgconfig.HTTPOK))

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(query) {
				t.Errorf("clickhouse test error want %s, got: %s", tc.pattern, query)
			}
		})
	}
}
