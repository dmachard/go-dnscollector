package collectors

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func Test_DnstapRelay(t *testing.T) {
	testcases := []struct {
		name       string
		mode       string
		address    string
		listenPort int
	}{
		{
			name:       "tcp_default",
			mode:       netutils.SocketTCP,
			address:    ":6000",
			listenPort: 0,
		},
		{
			name:       "tcp_custom_port",
			mode:       netutils.SocketTCP,
			address:    ":7100",
			listenPort: 7100,
		},
		{
			name:       "unix_default",
			mode:       netutils.SocketUnix,
			address:    "/tmp/dnscollector_relay.sock",
			listenPort: 0,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			g := pkgutils.NewFakeLogger()

			config := pkgconfig.GetFakeConfig()
			if tc.listenPort > 0 {
				config.Collectors.DnstapProxifier.ListenPort = tc.listenPort
			}
			if tc.mode == netutils.SocketUnix {
				config.Collectors.DnstapProxifier.SockPath = tc.address
			}

			// start collector
			c := NewDnstapProxifier([]pkgutils.Worker{g}, config, logger.New(false), "test")
			go c.StartCollect()

			// start client
			time.Sleep(1 * time.Second)
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
				dnsquery, err := dnsutils.GetFakeDNS()
				if err != nil {
					t.Fatalf("dns question pack error")
				}

				// get fake dnstap message
				dtQuery := processors.GetFakeDNSTap(dnsquery)

				// serialize to bytes
				data, err := proto.Marshal(dtQuery)
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
			msg := <-g.GetInputChannel()
			if len(msg.DNSTap.Payload) == 0 {
				t.Errorf("DNStap payload is empty")
			}

			c.Stop()
		})
	}
}
