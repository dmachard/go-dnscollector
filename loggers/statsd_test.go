package loggers

import (
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestStatsdRun(t *testing.T) {
	// init logger
	config := dnsutils.GetFakeConfig()
	config.Loggers.Statsd.FlushInterval = 1

	g := NewStatsdClient(config, logger.New(false), "1.2.3", "test")

	// fake msgpack receiver
	fakeRcvr, err := net.ListenPacket(dnsutils.SOCKET_UDP, "127.0.0.1:8125")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.Run()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDnsMessage()
	g.channel <- dm

	// read data on fake server side
	buf := make([]byte, 4096)
	n, _, err := fakeRcvr.ReadFrom(buf)
	if err != nil {
		t.Errorf("error to read data: %s", err)
	}

	if n == 0 {
		t.Errorf("no data received")
	}

}
