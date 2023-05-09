package transformers

import (
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestReducer_RepetitiveTrafficDetector(t *testing.T) {
	// enable feature
	config := dnsutils.GetFakeConfigTransformers()
	config.Reducer.Enable = true
	config.Reducer.RepetitiveTrafficDetector = true
	config.Reducer.WatchInterval = 1

	outChan := make(chan dnsutils.DnsMessage, 1)

	// init subproccesor
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, outChan)

	reducer := NewReducerSubprocessor(config, logger.New(false), "test", listChannel)
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
