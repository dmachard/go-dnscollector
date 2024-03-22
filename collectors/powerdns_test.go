package collectors

import (
	"log"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

func TestPowerDNS_Run(t *testing.T) {
	g := pkgutils.NewFakeLogger()

	c := NewProtobufPowerDNS([]pkgutils.Worker{g}, pkgconfig.GetFakeConfig(), logger.New(false), "test")
	if err := c.Listen(); err != nil {
		log.Fatal("collector powerdns  listening error: ", err)
	}
	go c.Run()

	conn, err := net.Dial(netlib.SocketTCP, ":6001")
	if err != nil {
		t.Error("could not connect to TCP server: ", err)
	}
	defer conn.Close()
}
