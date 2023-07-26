package transformers

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestReducer_Json(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()

	log := logger.New(false)
	outChans := []chan dnsutils.DnsMessage{}

	// get fake
	dm := dnsutils.GetFakeDnsMessage()
	dm.Init()

	// init subproccesor

	reducer := NewReducerSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	reducer.InitDnsMessage(&dm)

	// expected json
	refJson := `
			{
				"reducer": {
				  "occurences": 0,
				  "cumulative-length": 0
				}
			}
			`

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJson()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJson), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if _, ok := dmMap["reducer"]; !ok {
		t.Fatalf("transformer key is missing")
	}
	if !reflect.DeepEqual(dmMap["reducer"], refMap["reducer"]) {
		t.Errorf("json format different from reference")
	}
}

func TestReducer_RepetitiveTrafficDetector(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Reducer.Enable = true
	config.Reducer.RepetitiveTrafficDetector = true
	config.Reducer.WatchInterval = 1

	log := logger.New(false)
	outChan := make(chan dnsutils.DnsMessage, 1)
	outChans := []chan dnsutils.DnsMessage{}
	outChans = append(outChans, outChan)

	// init subproccesor
	reducer := NewReducerSubprocessor(config, logger.New(false), "test", 0, outChans, log.Info, log.Error)
	reducer.LoadActiveReducers()

	// malformed DNS message

	testcases := []struct {
		name           string
		dnsMessagesOut []dnsutils.DnsMessage
		dnsMessagesIn  []dnsutils.DnsMessage
	}{
		{
			name: "norepeat",
			dnsMessagesIn: []dnsutils.DnsMessage{
				{
					DnsTap:      dnsutils.DnsTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.Dns{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DnsNetInfo{QueryIp: "127.0.0.1"},
				},
				{
					DnsTap:      dnsutils.DnsTap{Operation: "CLIENT_RESPONSE"},
					DNS:         dnsutils.Dns{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DnsNetInfo{QueryIp: "127.0.0.1"},
				},
			},
			dnsMessagesOut: []dnsutils.DnsMessage{
				{
					Reducer: &dnsutils.TransformReducer{Occurences: 1},
				},
				{
					Reducer: &dnsutils.TransformReducer{Occurences: 1},
				},
			},
		},
		{
			name: "reduce",
			dnsMessagesIn: []dnsutils.DnsMessage{
				{
					DnsTap:      dnsutils.DnsTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.Dns{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DnsNetInfo{QueryIp: "127.0.0.1"},
				},
				{
					DnsTap:      dnsutils.DnsTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.Dns{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DnsNetInfo{QueryIp: "127.0.0.1"},
				},
			},
			dnsMessagesOut: []dnsutils.DnsMessage{
				{
					Reducer: &dnsutils.TransformReducer{Occurences: 2},
				},
			},
		},
		{
			name: "norepeat_qtype",
			dnsMessagesIn: []dnsutils.DnsMessage{
				{
					DnsTap:      dnsutils.DnsTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.Dns{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DnsNetInfo{QueryIp: "127.0.0.1"},
				},
				{
					DnsTap:      dnsutils.DnsTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.Dns{Qname: "hello.world", Qtype: "AAAA"},
					NetworkInfo: dnsutils.DnsNetInfo{QueryIp: "127.0.0.1"},
				},
			},
			dnsMessagesOut: []dnsutils.DnsMessage{
				{
					Reducer: &dnsutils.TransformReducer{Occurences: 1},
				},
				{
					Reducer: &dnsutils.TransformReducer{Occurences: 1},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			for _, dmIn := range tc.dnsMessagesIn {
				reducer.InitDnsMessage(&dmIn)
				ret := reducer.ProcessDnsMessage(&dmIn)
				if ret != RETURN_DROP {
					t.Errorf("DNS message should be dropped")
				}
			}

			time.Sleep(1 * time.Second)

			for _, dmRef := range tc.dnsMessagesOut {
				newDm := <-outChan
				if newDm.Reducer.Occurences != dmRef.Reducer.Occurences {
					t.Errorf("DNS message invalid repeated: Want=%d, Get=%d", dmRef.Reducer.Occurences, newDm.Reducer.Occurences)
				}
			}
		})
	}
}
