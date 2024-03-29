package transformers

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestReducer_Json(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()

	outChans := []chan dnsutils.DNSMessage{}

	// get fake
	dm := dnsutils.GetFakeDNSMessage()
	dm.Init()

	// init subproccesor

	reducer := NewReducerTransform(config, logger.New(false), "test", 0, outChans)
	reducer.InitDNSMessage(&dm)

	// expected json
	refJSON := `
			{
				"reducer": {
				  "occurrences": 0,
				  "cumulative-length": 0
				}
			}
			`

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJSON()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJSON), &refMap)
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
	config := pkgconfig.GetFakeConfigTransformers()
	config.Reducer.Enable = true
	config.Reducer.RepetitiveTrafficDetector = true
	config.Reducer.WatchInterval = 1

	outChan := make(chan dnsutils.DNSMessage, 1)
	outChans := []chan dnsutils.DNSMessage{}
	outChans = append(outChans, outChan)

	// init subproccesor
	reducer := NewReducerTransform(config, logger.New(false), "test", 0, outChans)
	reducer.LoadActiveReducers()

	// malformed DNS message
	testcases := []struct {
		name           string
		dnsMessagesOut []dnsutils.DNSMessage
		dnsMessagesIn  []dnsutils.DNSMessage
	}{
		{
			name: "norepeat",
			dnsMessagesIn: []dnsutils.DNSMessage{
				{
					DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
				},
				{
					DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_RESPONSE"},
					DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
				},
			},
			dnsMessagesOut: []dnsutils.DNSMessage{
				{
					Reducer: &dnsutils.TransformReducer{Occurrences: 1},
				},
				{
					Reducer: &dnsutils.TransformReducer{Occurrences: 1},
				},
			},
		},
		{
			name: "reduce",
			dnsMessagesIn: []dnsutils.DNSMessage{
				{
					DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
				},
				{
					DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
				},
			},
			dnsMessagesOut: []dnsutils.DNSMessage{
				{
					Reducer: &dnsutils.TransformReducer{Occurrences: 2},
				},
			},
		},
		{
			name: "norepeat_qtype",
			dnsMessagesIn: []dnsutils.DNSMessage{
				{
					DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
				},
				{
					DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "AAAA"},
					NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
				},
			},
			dnsMessagesOut: []dnsutils.DNSMessage{
				{
					Reducer: &dnsutils.TransformReducer{Occurrences: 1},
				},
				{
					Reducer: &dnsutils.TransformReducer{Occurrences: 1},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			for _, dmIn := range tc.dnsMessagesIn {
				reducer.InitDNSMessage(&dmIn)
				ret := reducer.ProcessDNSMessage(&dmIn)
				if ret != ReturnDrop {
					t.Errorf("DNS message should be dropped")
				}
			}

			time.Sleep(1 * time.Second)

			for _, dmRef := range tc.dnsMessagesOut {
				newDm := <-outChan
				if newDm.Reducer.Occurrences != dmRef.Reducer.Occurrences {
					t.Errorf("DNS message invalid repeated: Want=%d, Get=%d", dmRef.Reducer.Occurrences, newDm.Reducer.Occurrences)
				}
			}
		})
	}
}

func TestReducer_QnamePlusOne(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Reducer.Enable = true
	config.Reducer.RepetitiveTrafficDetector = true
	config.Reducer.QnamePlusOne = true
	config.Reducer.WatchInterval = 1

	outChan := make(chan dnsutils.DNSMessage, 1)
	outChans := []chan dnsutils.DNSMessage{}
	outChans = append(outChans, outChan)

	// init subproccesor
	reducer := NewReducerTransform(config, logger.New(false), "test", 0, outChans)
	reducer.LoadActiveReducers()

	testcases := []struct {
		name           string
		dnsMessagesOut []dnsutils.DNSMessage
		dnsMessagesIn  []dnsutils.DNSMessage
	}{
		{
			name: "reduce",
			dnsMessagesIn: []dnsutils.DNSMessage{
				{
					DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.DNS{Qname: "test1.hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
				},
				{
					DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
					DNS:         dnsutils.DNS{Qname: "test2.hello.world", Qtype: "A"},
					NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
				},
			},
			dnsMessagesOut: []dnsutils.DNSMessage{
				{
					Reducer: &dnsutils.TransformReducer{Occurrences: 2},
				},
			},
		},
	}

	// run all testcases
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			for _, dmIn := range tc.dnsMessagesIn {
				reducer.InitDNSMessage(&dmIn)
				ret := reducer.ProcessDNSMessage(&dmIn)
				if ret != ReturnDrop {
					t.Errorf("DNS message should be dropped")
				}
			}

			time.Sleep(1 * time.Second)

			for _, dmRef := range tc.dnsMessagesOut {
				newDm := <-outChan
				if newDm.Reducer.Occurrences != dmRef.Reducer.Occurrences {
					t.Errorf("DNS message invalid repeated: Want=%d, Get=%d", dmRef.Reducer.Occurrences, newDm.Reducer.Occurrences)
				}
			}
		})
	}
}
