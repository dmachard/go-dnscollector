package generators

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

func GetLogger() *logger.Logger {
	logger := logger.New(false)
	return logger
}

func GetFakeConfig() *common.Config {
	config := &common.Config{}
	return config
}

func GetFakeDnsMessage() dnsmessage.DnsMessage {
	dm := dnsmessage.DnsMessage{}
	dm.Init()
	dm.Operation = "CLIENT_QUERY"
	dm.Type = "query"
	dm.Qname = "dns.collector"
	dm.QueryIp = "1.2.3.4"
	dm.Rcode = "NOERROR"
	dm.Qtype = "A"
	return dm
}

func TestServerMetrics(t *testing.T) {
	// init the generator
	g := NewWebserver(GetFakeConfig(), GetLogger())

	// record one dns message to simulate some incoming data
	g.stats.Record(GetFakeDnsMessage())

	// init httptest
	request := httptest.NewRequest(http.MethodGet, "/metrics", strings.NewReader(""))
	responseRecorder := httptest.NewRecorder()

	// call handler
	g.metricsHandler(responseRecorder, request)

	// checking status code
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
	}

	// checking content
	var pattern = `dnscollector_queries_total 1`
	metrics := strings.TrimSpace(responseRecorder.Body.String())
	if regexp.MustCompile(pattern).MatchString(string(metrics)) != true {
		t.Errorf("Want '%s', got '%s'", pattern, responseRecorder.Body)
	}
}

func TestServerDomains(t *testing.T) {
	// init the generator
	g := NewWebserver(GetFakeConfig(), GetLogger())

	// record one dns message to simulate some incoming data
	g.stats.Record(GetFakeDnsMessage())

	// init httptest
	request := httptest.NewRequest(http.MethodGet, "/tables/domains", strings.NewReader(""))
	responseRecorder := httptest.NewRecorder()

	// call handler
	g.tablesDomainsHandler(responseRecorder, request)

	// checking status code
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
	}

	// checking content
	domains := strings.TrimSpace(responseRecorder.Body.String())
	want := `[{"key":"dns.collector","hit":1}]`
	if strings.TrimSpace(responseRecorder.Body.String()) != want {
		t.Errorf("Want '%s', got '%s'", want, domains)
	}
}

func TestServerClients(t *testing.T) {
	// init the generator
	g := NewWebserver(GetFakeConfig(), GetLogger())

	// record one dns message to simulate some incoming data
	g.stats.Record(GetFakeDnsMessage())

	// init httptest
	request := httptest.NewRequest(http.MethodGet, "/tables/clients", strings.NewReader(""))
	responseRecorder := httptest.NewRecorder()

	// call handler
	g.tablesClientsHandler(responseRecorder, request)

	// checking status code
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
	}

	// checking content
	domains := strings.TrimSpace(responseRecorder.Body.String())
	want := `[{"key":"1.2.3.4","hit":1}]`
	if strings.TrimSpace(responseRecorder.Body.String()) != want {
		t.Errorf("Want '%s', got '%s'", want, domains)
	}
}

func TestServerRcodes(t *testing.T) {
	// init the generator
	g := NewWebserver(GetFakeConfig(), GetLogger())

	// record one dns message to simulate some incoming data
	g.stats.Record(GetFakeDnsMessage())

	// init httptest
	request := httptest.NewRequest(http.MethodGet, "/tables/rcodes", strings.NewReader(""))
	responseRecorder := httptest.NewRecorder()

	// call handler
	g.tablesRcodesHandler(responseRecorder, request)

	// checking status code
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
	}

	// checking content
	domains := strings.TrimSpace(responseRecorder.Body.String())
	want := `[{"key":"NOERROR","hit":1}]`
	if strings.TrimSpace(responseRecorder.Body.String()) != want {
		t.Errorf("Want '%s', got '%s'", want, domains)
	}
}

func TestServerRrtypes(t *testing.T) {
	// init the generator
	g := NewWebserver(GetFakeConfig(), GetLogger())

	// record one dns message to simulate some incoming data
	g.stats.Record(GetFakeDnsMessage())

	// init httptest
	request := httptest.NewRequest(http.MethodGet, "/tables/rrtypes", strings.NewReader(""))
	responseRecorder := httptest.NewRecorder()

	// call handler
	g.tablesRrtypesHandler(responseRecorder, request)

	// checking status code
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
	}

	// checking content
	domains := strings.TrimSpace(responseRecorder.Body.String())
	want := `[{"key":"A","hit":1}]`
	if strings.TrimSpace(responseRecorder.Body.String()) != want {
		t.Errorf("Want '%s', got '%s'", want, domains)
	}
}

func TestServerOperations(t *testing.T) {
	// init the generator
	g := NewWebserver(GetFakeConfig(), GetLogger())

	// record one dns message to simulate some incoming data
	g.stats.Record(GetFakeDnsMessage())

	// init httptest
	request := httptest.NewRequest(http.MethodGet, "/tables/operations", strings.NewReader(""))
	responseRecorder := httptest.NewRecorder()

	// call handler
	g.tablesOperationsHandler(responseRecorder, request)

	// checking status code
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
	}

	// checking content
	domains := strings.TrimSpace(responseRecorder.Body.String())
	want := `[{"key":"CLIENT_QUERY","hit":1}]`
	if strings.TrimSpace(responseRecorder.Body.String()) != want {
		t.Errorf("Want '%s', got '%s'", want, domains)
	}
}
