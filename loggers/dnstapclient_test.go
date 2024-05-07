package loggers

import (
	"bufio"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/segmentio/kafka-go/compress"
	"google.golang.org/protobuf/proto"
)

func Test_DnstapClient(t *testing.T) {

	testcases := []struct {
		name        string
		transport   string
		address     string
		compression string
	}{
		{
			name:        "dnstap_tcp",
			transport:   "tcp",
			address:     ":6000",
			compression: "none",
		},
		{
			name:        "dnstap_unix",
			transport:   "unix",
			address:     "/tmp/test.sock",
			compression: "none",
		},
		{
			name:        "dnstap_tcp_gzip_compress",
			transport:   "tcp",
			address:     ":6000",
			compression: "gzip",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// init logger
			cfg := pkgconfig.GetFakeConfig()
			cfg.Loggers.DNSTap.FlushInterval = 1
			cfg.Loggers.DNSTap.BufferSize = 0
			cfg.Loggers.DNSTap.Compression = tc.compression
			if tc.transport == "unix" {
				cfg.Loggers.DNSTap.SockPath = tc.address
			}

			g := NewDnstapSender(cfg, logger.New(false), "test")

			// fake dnstap receiver
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

			// init framestream on server side
			fsSvr := framestream.NewFstrm(bufio.NewReader(conn), bufio.NewWriter(conn), conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
			if err := fsSvr.InitReceiver(); err != nil {
				t.Errorf("error to init framestream receiver: %s", err)
			}

			// wait framestream to be ready
			time.Sleep(time.Second)

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dm

			// receive frame on server side ?, timeout 5s
			var fs *framestream.Frame
			if tc.compression == "gzip" {
				fs, err = fsSvr.RecvCompressedFrame(&compress.GzipCodec, true)
			} else {
				fs, err = fsSvr.RecvFrame(true)
			}
			if err != nil {
				t.Errorf("error to receive frame: %s", err)
			}

			// decode the dnstap message in server side
			dt := &dnstap.Dnstap{}
			if cfg.Loggers.DNSTap.Compression == pkgconfig.CompressNone {
				if err := proto.Unmarshal(fs.Data(), dt); err != nil {
					t.Errorf("error to decode dnstap")
				}
			} else {
				// ignore first 4 bytes
				data := fs.Data()[4:]
				validFrame := true
				for len(data) >= 4 {
					// get frame size
					payloadSize := binary.BigEndian.Uint32(data[:4])
					data = data[4:]

					// enough next data ?
					if uint32(len(data)) < payloadSize {
						validFrame = false
						break
					}

					if err := proto.Unmarshal(data[:payloadSize], dt); err != nil {
						t.Errorf("error to decode dnstap from compressed frame")
					}

					// continue for next
					data = data[payloadSize:]
				}
				if !validFrame {
					t.Errorf("invalid compressed frame")
				}
			}
		})
	}
}
