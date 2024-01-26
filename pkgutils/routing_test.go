package pkgutils

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_RoutingHandler_AddDefaultRoute(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 10)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// create routing handler
	rh := NewRoutingHandler(pkgconfig.GetFakeConfig(), lg, "test")

	// add default routes
	nxt := NewFakeLogger()
	rh.AddDefaultRoute(nxt)

	// get default routes
	defaultRoutes, defaultNames := rh.GetDefaultRoutes()

	// send dns message
	dmIn := dnsutils.GetFakeDNSMessage()
	rh.SendTo(defaultRoutes, defaultNames, dmIn)

	// read dns message from next item
	dmOut := <-nxt.GetInputChannel()
	if dmOut.DNS.Qname != "dns.collector" {
		t.Errorf("invalid qname in dns message: %s", dmOut.DNS.Qname)
	}

	// stop
	rh.Stop()
}
