package loggers

import (
	"bufio"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func Test_RedisPubRun(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    dnsutils.MODE_TEXT,
			pattern: " dns.collector ",
		},
		{
			mode:    dnsutils.MODE_JSON,
			pattern: `\\\"qname\\\":\\\"dns.collector\\\"`,
		},
		{
			mode:    dnsutils.MODE_FLATJSON,
			pattern: `\\\"dns.qname\\\":\\\"dns.collector\\\"`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			cfg := dnsutils.GetFakeConfig()
			cfg.Loggers.RedisPub.FlushInterval = 1
			cfg.Loggers.RedisPub.BufferSize = 0
			cfg.Loggers.RedisPub.Mode = tc.mode
			cfg.Loggers.RedisPub.RedisChannel = "testons"

			g := NewRedisPub(cfg, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(dnsutils.SOCKET_TCP, ":6379")
			if err != nil {
				t.Fatal(err)
			}
			defer fakeRcvr.Close()

			// start the logger
			go g.Run()

			// accept conn from logger
			conn, err := fakeRcvr.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// wait connection on logger
			time.Sleep(time.Second)

			// send fake dns message to logger
			dm := dnsutils.GetFakeDnsMessage()
			g.channel <- dm

			// read data on server side and decode-it
			reader := bufio.NewReader(conn)
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(line) {
				t.Errorf("redis error want %s, got: %s", tc.pattern, line)
			}

			pattern2 := regexp.MustCompile("PUBLISH \"testons\"")
			if !pattern2.MatchString(line) {
				t.Errorf("redis error want %s, got: %s", pattern2, line)
			}
		})
	}
}
