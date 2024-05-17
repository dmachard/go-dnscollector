package workers

import (
	"bufio"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

func Test_RedisPubRun(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    pkgconfig.ModeText,
			pattern: " dns.collector ",
		},
		{
			mode:    pkgconfig.ModeJSON,
			pattern: `\\\"qname\\\":\\\"dns.collector\\\"`,
		},
		{
			mode:    pkgconfig.ModeFlatJSON,
			pattern: `\\\"dns.qname\\\":\\\"dns.collector\\\"`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			cfg := pkgconfig.GetDefaultConfig()
			cfg.Loggers.RedisPub.FlushInterval = 1
			cfg.Loggers.RedisPub.BufferSize = 0
			cfg.Loggers.RedisPub.Mode = tc.mode
			cfg.Loggers.RedisPub.RedisChannel = "testons"

			g := NewRedisPub(cfg, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(netutils.SocketTCP, ":6379")
			if err != nil {
				t.Fatal(err)
			}
			defer fakeRcvr.Close()

			// start the logger
			go g.StartCollect()

			// accept conn from logger
			conn, err := fakeRcvr.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// wait connection on logger
			time.Sleep(time.Second)

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dm

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

			// stop all
			fakeRcvr.Close()
			g.Stop()
		})
	}
}
