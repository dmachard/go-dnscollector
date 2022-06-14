package loggers

import (
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestInfluxDBRun(t *testing.T) {
	// init logger
	g := NewInfluxDBClient(dnsutils.GetFakeConfig(), logger.New(false), "test")

	// fake msgpack receiver
	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:8086")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.Run()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDnsMessage()
	g.channel <- dm

	// accept conn
	conn, err := fakeRcvr.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// read data on fake server side
	buf := make([]byte, 4096)
	_, err = conn.Read(buf)
	if err != nil {
		t.Errorf("error to read data: %s", err)
	}
}
