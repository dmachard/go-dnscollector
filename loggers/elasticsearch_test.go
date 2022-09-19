package loggers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestElasticSearchClientRun(t *testing.T) {

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	}))

	conf := dnsutils.GetFakeConfig()
	conf.Loggers.ElasticSearchClient.URL = svr.URL

	g := NewElasticSearchClient(conf, logger.New(false), "test")

	go g.Run()

	dm := dnsutils.GetFakeDnsMessage()
	g.channel <- dm
}
