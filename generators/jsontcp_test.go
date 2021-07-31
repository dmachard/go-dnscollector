package generators

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
)

func TestJsonTcpRun(t *testing.T) {
	// init generator
	g := NewJsonTcpSender(common.GetFakeConfig(), common.GetFakeLogger(false))

	// fake json receiver
	fakeRcvr, err := net.Listen("tcp", ":9999")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the generator
	go g.Run()

	// accept conn from generator
	conn, err := fakeRcvr.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// send fake dns message to generator
	dm := common.GetFakeDnsMessage()
	g.channel <- dm

	// read data on server side and decode-it
	reader := bufio.NewReader(conn)
	var dmRcv dnsmessage.DnsMessage
	if err := json.NewDecoder(reader).Decode(&dmRcv); err != nil {
		t.Errorf("error to decode json: %s", err)
	}
	if dm.Qname != dmRcv.Qname {
		t.Errorf("qname error want %s, got %s", dm.Qname, dmRcv.Qname)
	}
}
