package loggers

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/stretchr/testify/assert"
)

func Test_ElasticSearchClient_BulkSize_Exceeded(t *testing.T) {

	testcases := []struct {
		mode      string
		bulkSize  int
		inputSize int
	}{
		{
			mode:      pkgconfig.ModeFlatJSON,
			bulkSize:  1024,
			inputSize: 15,
		},
	}

	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:59200")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			conf := pkgconfig.GetFakeConfig()
			conf.Loggers.ElasticSearchClient.Index = "indexname"
			conf.Loggers.ElasticSearchClient.Server = "http://127.0.0.1:59200/"
			conf.Loggers.ElasticSearchClient.BulkSize = tc.bulkSize
			g := NewElasticSearchClient(conf, logger.New(false), "test")

			go g.Run()

			dm := dnsutils.GetFakeDNSMessage()

			for i := 0; i < tc.inputSize; i++ {
				g.GetInputChannel() <- dm
			}

			totalDm := 0
			for i := 0; i < tc.inputSize; i++ {
				// accept conn
				conn, err := fakeRcvr.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()

				// read and parse http request on server side
				connReader := bufio.NewReader(conn)
				connReaderT := bufio.NewReaderSize(connReader, tc.bulkSize*2)
				request, err := http.ReadRequest(connReaderT)
				if err != nil {
					t.Fatal(err)
				}
				conn.Write([]byte(pkgconfig.HTTPOK))

				// read payload from request body
				payload, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}

				scanner := bufio.NewScanner(strings.NewReader(string(payload)))

				cnt := 0
				for scanner.Scan() {
					if cnt%2 == 0 {
						var res map[string]interface{}
						json.Unmarshal(scanner.Bytes(), &res)
						assert.Equal(t, map[string]interface{}{}, res["create"])
					} else {
						var bulkDm dnsutils.DNSMessage
						err := json.Unmarshal(scanner.Bytes(), &bulkDm)
						assert.NoError(t, err)
						totalDm += 1
					}
					cnt++
				}

			}
			assert.Equal(t, tc.inputSize, totalDm)
		})
	}
}

func Test_ElasticSearchClient_FlushInterval_Exceeded(t *testing.T) {

	testcases := []struct {
		mode          string
		bulkSize      int
		inputSize     int
		flushInterval int
	}{
		{
			mode:          pkgconfig.ModeFlatJSON,
			bulkSize:      1048576,
			inputSize:     50,
			flushInterval: 1,
		},
	}

	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:59200")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		totalDm := 0
		t.Run(tc.mode, func(t *testing.T) {
			conf := pkgconfig.GetFakeConfig()
			conf.Loggers.ElasticSearchClient.Index = "indexname"
			conf.Loggers.ElasticSearchClient.Server = "http://127.0.0.1:59200/"
			conf.Loggers.ElasticSearchClient.BulkSize = tc.bulkSize
			conf.Loggers.ElasticSearchClient.FlushInterval = tc.flushInterval
			g := NewElasticSearchClient(conf, logger.New(false), "test")

			go g.Run()

			dm := dnsutils.GetFakeDNSMessage()

			for i := 0; i < tc.inputSize; i++ {
				g.GetInputChannel() <- dm
			}
			// accept the connection
			// the connection should contains all packets
			conn, err := fakeRcvr.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			connReader := bufio.NewReader(conn)
			connReaderT := bufio.NewReaderSize(connReader, tc.bulkSize*2)
			request, err := http.ReadRequest(connReaderT)
			if err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte(pkgconfig.HTTPOK))

			// read payload from request body
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}

			scanner := bufio.NewScanner(strings.NewReader(string(payload)))
			cnt := 0
			for scanner.Scan() {
				if cnt%2 == 0 {
					var res map[string]interface{}
					json.Unmarshal(scanner.Bytes(), &res)
					assert.Equal(t, map[string]interface{}{}, res["create"])
				} else {
					var bulkDm dnsutils.DNSMessage
					err := json.Unmarshal(scanner.Bytes(), &bulkDm)
					assert.NoError(t, err)
					totalDm += 1
				}
				cnt++
			}

		})
		assert.Equal(t, tc.inputSize, totalDm)
	}
}
