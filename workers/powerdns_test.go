package workers

import (
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
)

func TestPowerDNS_Run(t *testing.T) {
	g := pkgutils.NewFakeLogger()

	c := NewProtobufPowerDNS([]pkgutils.Worker{g}, pkgconfig.GetFakeConfig(), logger.New(false), "test")
	go c.StartCollect()

	// wait before to connect
	time.Sleep(1 * time.Second)
	conn, err := net.Dial(netutils.SocketTCP, ":6001")
	if err != nil {
		t.Error("could not connect to TCP server: ", err)
	}
	defer conn.Close()
}
