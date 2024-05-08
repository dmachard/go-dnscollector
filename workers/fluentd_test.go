package workers

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/IBM/fluent-forward-go/fluent/protocol"
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/tinylib/msgp/msgp"
)

func Test_FluentdClient(t *testing.T) {
	testcases := []struct {
		name          string
		transport     string
		address       string
		bufferSize    int
		flushInterval int
	}{
		{
			name:          "with_buffer",
			transport:     netutils.SocketTCP,
			address:       ":24224",
			bufferSize:    100,
			flushInterval: 1,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// init logger
			cfg := pkgconfig.GetFakeConfig()
			cfg.Loggers.Fluentd.FlushInterval = tc.flushInterval
			cfg.Loggers.Fluentd.BufferSize = tc.bufferSize
			g := NewFluentdClient(cfg, logger.New(false), "test")

			// fake msgpack receiver
			fakeRcvr, err := net.Listen(tc.transport, tc.address)
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
			time.Sleep(time.Second)

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			maxDm := 256
			for i := 0; i < maxDm; i++ {
				g.GetInputChannel() <- dm
			}
			time.Sleep(time.Second)

			// read data on fake server side
			nb := 0
			bytesSize := 0
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			fullBuffer := make([]byte, 0)
			for {
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				if n == 0 {
					break
				}
				bytesSize += n
				fullBuffer = append(fullBuffer, buf[:n]...)
			}

			// code msgpack
			msgpr := msgp.NewReader(bytes.NewReader(fullBuffer[:bytesSize]))
			for {
				sz, err := msgpr.ReadArrayHeader()
				if err != nil {
					t.Errorf("decode Array Header failed: %v", err)
					break
				}
				if sz != 3 {
					t.Errorf("decode expect 3 elements: %d", sz)
					break
				}
				tag, err := msgpr.ReadString()
				if err != nil {
					t.Errorf("Decode tag: %v", err)
					break
				}
				if tag != "dns.collector" {
					t.Errorf("invalid tag: %s", tag)
					break
				}

				entries := protocol.EntryList{}
				if err = entries.DecodeMsg(msgpr); err != nil {
					t.Errorf("decode Entries: %v", err)
					break
				}
				nb += len(entries)

				options := &protocol.MessageOptions{}
				if err = options.DecodeMsg(msgpr); err != nil {
					t.Errorf("decode options: %v", err)
					break
				}

				if msgpr.Buffered() == 0 {
					break
				}
			}

			if nb != maxDm {
				t.Errorf("invalid numer of msgpack: expected=%d received=%d", maxDm, nb)
			}

			// stop all
			fakeRcvr.Close()
			g.Stop()
		})
	}
}
