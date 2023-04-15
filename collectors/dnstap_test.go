package collectors

import (
	"bufio"
	"log"
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func Test_DnstapCollector(t *testing.T) {
	testcases := []struct {
		name        string
		mode        string
		address     string
		listen_port int
		operation   string
	}{
		{
			name:        "tcp_default",
			mode:        dnsutils.SOCKET_TCP,
			address:     ":6000",
			listen_port: 0,
			operation:   "CLIENT_QUERY",
		},
		{
			name:        "tcp_custom_port",
			mode:        dnsutils.SOCKET_TCP,
			address:     ":7000",
			listen_port: 7000,
			operation:   "CLIENT_QUERY",
		},
		{
			name:        "unix_default",
			mode:        dnsutils.SOCKET_UNIX,
			address:     "/tmp/dnscollector.sock",
			listen_port: 0,
			operation:   "CLIENT_QUERY",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			g := loggers.NewFakeLogger()

			config := dnsutils.GetFakeConfig()
			if tc.listen_port > 0 {
				config.Collectors.Dnstap.ListenPort = tc.listen_port
			}
			if tc.mode == dnsutils.SOCKET_UNIX {
				config.Collectors.Dnstap.SockPath = tc.address
			}

			c := NewDnstap([]dnsutils.Worker{g}, config, logger.New(false), "test")
			if err := c.Listen(); err != nil {
				log.Fatal("collector listening  error: ", err)
			}

			go c.Run()

			conn, err := net.Dial(tc.mode, tc.address)
			if err != nil {
				t.Error("could not connect: ", err)
			}
			defer conn.Close()

			r := bufio.NewReader(conn)
			w := bufio.NewWriter(conn)
			fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
			if err := fs.InitSender(); err != nil {
				t.Fatalf("framestream init error: %s", err)
			} else {
				frame := &framestream.Frame{}

				// get fake dns question
				dnsquery, err := GetFakeDns()
				if err != nil {
					t.Fatalf("dns question pack error")
				}

				// get fake dnstap message
				dt_query := GetFakeDnstap(dnsquery)

				// serialize to bytes
				data, err := proto.Marshal(dt_query)
				if err != nil {
					t.Fatalf("dnstap proto marshal error %s", err)
				}

				// send query
				frame.Write(data)
				if err := fs.SendFrame(frame); err != nil {
					t.Fatalf("send frame error %s", err)
				}
			}

			// waiting message in channel
			msg := <-g.Channel()
			if msg.DnsTap.Operation != tc.operation {
				t.Errorf("want %s, got %s", tc.operation, msg.DnsTap.Operation)
			}

			c.Stop()
		})
	}
}
