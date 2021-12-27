package loggers

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestTcpClientJsonRun(t *testing.T) {
	// init logger
	g := NewTcpClient(dnsutils.GetFakeConfig(), logger.New(false))

	// fake json receiver
	fakeRcvr, err := net.Listen("tcp", ":9999")
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
	dm := dnsutils.GetFakeDnsMessage()
	g.channel <- dm

	// read data on server side and decode-it
	reader := bufio.NewReader(conn)
	var dmRcv dnsutils.DnsMessage
	if err := json.NewDecoder(reader).Decode(&dmRcv); err != nil {
		t.Errorf("error to decode json: %s", err)
	}
	if dm.DNS.Qname != dmRcv.DNS.Qname {
		t.Errorf("qname error want %s, got %s", dm.DNS.Qname, dmRcv.DNS.Qname)
	}
}
