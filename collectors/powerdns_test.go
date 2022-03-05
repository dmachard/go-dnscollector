package collectors

import (
	"log"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-logger"
)

func TestProbufPdnsRun(t *testing.T) {
	g := loggers.NewFakeLogger()
	c := NewProtobufPowerDNS([]dnsutils.Worker{g}, dnsutils.GetFakeConfig(), logger.New(false))
	if err := c.Listen(); err != nil {
		log.Fatal("collector powerdns  listening error: ", err)
	}
	go c.Run()

	conn, err := net.Dial("tcp", ":6001")
	if err != nil {
		t.Error("could not connect to TCP server: ", err)
	}
	defer conn.Close()
}
