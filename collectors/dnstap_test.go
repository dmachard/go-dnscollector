package collectors

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/segmentio/kafka-go/compress"
	"google.golang.org/protobuf/proto"
)

func Test_DnstapCollector(t *testing.T) {
	testcases := []struct {
		name        string
		mode        string
		address     string
		listenPort  int
		operation   string
		compression string
	}{
		{
			name:        "tcp_default",
			mode:        netlib.SocketTCP,
			address:     ":6000",
			listenPort:  0,
			operation:   "CLIENT_QUERY",
			compression: "none",
		},
		{
			name:        "tcp_custom_port",
			mode:        netlib.SocketTCP,
			address:     ":7000",
			listenPort:  7000,
			operation:   "CLIENT_QUERY",
			compression: "none",
		},
		{
			name:        "unix_default",
			mode:        netlib.SocketUnix,
			address:     "/tmp/dnscollector.sock",
			listenPort:  0,
			operation:   "CLIENT_QUERY",
			compression: "none",
		},
		{
			name:        "tcp_compress_gzip",
			mode:        netlib.SocketTCP,
			address:     ":7000",
			listenPort:  7000,
			operation:   "CLIENT_QUERY",
			compression: "gzip",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			g := pkgutils.NewFakeLogger()

			config := pkgconfig.GetFakeConfig()
			if tc.listenPort > 0 {
				config.Collectors.Dnstap.ListenPort = tc.listenPort
			}
			if tc.mode == netlib.SocketUnix {
				config.Collectors.Dnstap.SockPath = tc.address
			}
			config.Collectors.Dnstap.Compression = tc.compression

			// start the collector
			c := NewDnstap([]pkgutils.Worker{g}, config, logger.New(false), "test")
			go c.Run()

			// wait before to connect
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
				bulkFrame := &framestream.Frame{}
				subFrame := &framestream.Frame{}

				// get fake dns question
				dnsquery, err := processors.GetFakeDNS()
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

				if config.Collectors.Dnstap.Compression == pkgconfig.CompressNone {
					// send the frame
					bulkFrame.Write(data)
					if err := fs.SendFrame(bulkFrame); err != nil {
						t.Fatalf("send frame error %s", err)
					}
				} else {
					subFrame.Write(data)
					bulkFrame.AppendData(subFrame.Data())
				}

				if config.Collectors.Dnstap.Compression != pkgconfig.CompressNone {
					bulkFrame.Encode()
					if err := fs.SendCompressedFrame(&compress.GzipCodec, bulkFrame); err != nil {
						t.Fatalf("send compressed frame error %s", err)
					}
				}
			}

			// waiting message in channel
			msg := <-g.GetInputChannel()
			if msg.DNSTap.Operation != tc.operation {
				t.Errorf("want %s, got %s", tc.operation, msg.DNSTap.Operation)
			}

			c.Stop()
		})
	}
}

// Testcase for https://github.com/dmachard/go-dnscollector/issues/461
// Support Bind9 with dnstap closing.
func Test_DnstapCollector_CloseFrameStream(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 50)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	config := pkgconfig.GetFakeConfig()
	config.Collectors.Dnstap.SockPath = "/tmp/dnscollector.sock"

	// start the collector in unix mode
	g := pkgutils.NewFakeLogger()
	c := NewDnstap([]pkgutils.Worker{g}, config, lg, "test")
	go c.Run()

	// simulate dns server connection to collector
	time.Sleep(1 * time.Second)
	conn, err := net.Dial(netlib.SocketUnix, "/tmp/dnscollector.sock")
	if err != nil {
		t.Error("could not connect: ", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
	if err := fs.InitSender(); err != nil {
		t.Fatalf("framestream init error: %s", err)
	}

	// checking reset
	errClose := fs.ResetSender()
	if errClose != nil {
		t.Errorf("reset sender error: %s", errClose)
	}

	regxp := ".*framestream reseted by sender.*"
	pattern := regexp.MustCompile(regxp)

	matchMsg := false
	for entry := range logsChan {
		fmt.Println(entry)
		if pattern.MatchString(entry.Message) {
			matchMsg = true
			break
		}
	}
	if !matchMsg {
		t.Errorf("reset from sender not received")
	}

	// cleanup
	c.Stop()
}
