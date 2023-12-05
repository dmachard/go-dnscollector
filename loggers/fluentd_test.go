package loggers

import (
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/vmihailenco/msgpack"
)

func Test_FluentdClient(t *testing.T) {
	testcases := []struct {
		transport string
		address   string
	}{
		{
			transport: pkgconfig.SocketTCP,
			address:   ":24224",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.transport, func(t *testing.T) {
			// init logger
			cfg := pkgconfig.GetFakeConfig()
			cfg.Loggers.Fluentd.FlushInterval = 1
			cfg.Loggers.Fluentd.BufferSize = 0
			g := NewFluentdClient(cfg, logger.New(false), "test")

			// fake msgpack receiver
			fakeRcvr, err := net.Listen(tc.transport, tc.address)
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

			// send fake dns message to logger
			time.Sleep(time.Second)
			dm := dnsutils.GetFakeDNSMessage()
			g.Channel() <- dm

			// read data on fake server side
			buf := make([]byte, 4096)
			_, err = conn.Read(buf)
			if err != nil {
				t.Errorf("error to read msgpack: %s", err)
			}

			// unpack msgpack
			var dmRcv dnsutils.DNSMessage
			err = msgpack.Unmarshal(buf[24:], &dmRcv)
			if err != nil {
				t.Errorf("error to unpack msgpack: %s", err)
			}
			if dm.DNS.Qname != dmRcv.DNS.Qname {
				t.Errorf("qname error want %s, got %s", dm.DNS.Qname, dmRcv.DNS.Qname)
			}

			// stop all
			fakeRcvr.Close()
			g.Stop()
		})
	}
}
