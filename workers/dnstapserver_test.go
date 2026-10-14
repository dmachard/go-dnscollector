package workers

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/pkg/telemetry"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/miekg/dns"
	"github.com/segmentio/kafka-go/compress"
	"google.golang.org/protobuf/proto"
)

func Test_DnstapCollector(t *testing.T) {
	testcases := []struct {
		name        string
		mode        string
		address     string
		listenPort  int
		operation   string
		compression string
	}{
		{
			name:        "tcp_default",
			mode:        netutils.SocketTCP,
			address:     ":6000",
			listenPort:  0,
			operation:   "CLIENT_QUERY",
			compression: "none",
		},
		{
			name:        "tcp_custom_port",
			mode:        netutils.SocketTCP,
			address:     ":7000",
			listenPort:  7000,
			operation:   "CLIENT_QUERY",
			compression: "none",
		},
		{
			name:        "unix_default",
			mode:        netutils.SocketUnix,
			address:     "/tmp/dnscollector.sock",
			listenPort:  0,
			operation:   "CLIENT_QUERY",
			compression: "none",
		},
		{
			name:        "tcp_compress_gzip",
			mode:        netutils.SocketTCP,
			address:     ":7000",
			listenPort:  7000,
			operation:   "CLIENT_QUERY",
			compression: "gzip",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			g := GetWorkerForTest(config.DefaultBufferSize)

			cfg := config.GetDefaultConfig()
			if tc.listenPort > 0 {
				cfg.Collectors.Dnstap.ListenPort = tc.listenPort
			}
			if tc.mode == netutils.SocketUnix {
				cfg.Collectors.Dnstap.SockPath = tc.address
			}
			cfg.Collectors.Dnstap.Compression = tc.compression

			// start the collector
			c := NewDnstapServer([]Worker{g}, cfg, logger.New(false), "test")
			go c.StartCollect()

			// wait before to connect
			time.Sleep(1 * time.Second)
			conn, err := net.Dial(tc.mode, tc.address)
			if err != nil {
				t.Error("could not connect: ", err)
			}
			defer conn.Close()

			r := bufio.NewReader(conn)
			w := bufio.NewWriter(conn)
			fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
			if err := fs.InitSender(); err != nil {
				t.Fatalf("framestream init error: %s", err)
			} else {
				bulkFrame := &framestream.Frame{}
				subFrame := &framestream.Frame{}

				// get fake dns question
				dnsquery, err := dnsutils.GetFakeDNS()
				if err != nil {
					t.Fatalf("dns question pack error")
				}

				// get fake dnstap message
				dtQuery := GetFakeDNSTap(dnsquery)

				// serialize to bytes
				data, err := proto.Marshal(dtQuery)
				if err != nil {
					t.Fatalf("dnstap proto marshal error %s", err)
				}
				// send query

				if cfg.Collectors.Dnstap.Compression == config.CompressNone {
					// send the frame
					bulkFrame.Write(data)
					if err := fs.SendFrame(bulkFrame); err != nil {
						t.Fatalf("send frame error %s", err)
					}
				} else {
					subFrame.Write(data)
					bulkFrame.AppendData(subFrame.Data())
				}

				if cfg.Collectors.Dnstap.Compression != config.CompressNone {
					bulkFrame.Encode()
					if err := fs.SendCompressedFrame(&compress.GzipCodec, bulkFrame); err != nil {
						t.Fatalf("send compressed frame error %s", err)
					}
				}
			}

			// waiting message in channel
			batch := <-g.GetInputChannel()
			if len(batch.Messages) == 0 || batch.Messages[0].DNSTap.Operation != tc.operation {
				t.Errorf("want %s, got %v", tc.operation, batch.Messages)
			}

			c.Stop()
		})
	}
}

// Testcase for https://github.com/dmachard/go-dnscollector/v3/issues/461
// Support Bind9 with dnstap closing.
func Test_DnstapCollector_CloseFrameStream(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 50)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.SockPath = "/tmp/dnscollector.sock"

	// start the collector in unix mode
	g := GetWorkerForTest(config.DefaultBufferSize)
	c := NewDnstapServer([]Worker{g}, cfg, lg, "test")
	go c.StartCollect()

	// simulate dns server connection to collector
	time.Sleep(1 * time.Second)
	conn, err := net.Dial(netutils.SocketUnix, "/tmp/dnscollector.sock")
	if err != nil {
		t.Error("could not connect: ", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
	if err := fs.InitSender(); err != nil {
		t.Fatalf("framestream init error: %s", err)
	}

	// checking reset
	errClose := fs.ResetSender()
	if errClose != nil {
		t.Errorf("reset sender error: %s", errClose)
	}

	regxp := ".*framestream reset by sender.*"
	pattern := regexp.MustCompile(regxp)

	matchMsg := false
	for entry := range logsChan {
		fmt.Println(entry)
		if pattern.MatchString(entry.Message) {
			matchMsg = true
			break
		}
	}
	if !matchMsg {
		t.Errorf("reset from sender not received")
	}

	// cleanup
	c.Stop()
}

func Test_DnstapProcessor_toDNSMessage(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, "peertest", config.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion(config.ExpectedQname+".", dns.TypeA)
	dnsquestion, _ := dnsmsg.Pack()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion

	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNS.Qname != config.ExpectedQname {
		t.Errorf("invalid qname in dns message: %v", batch.Messages)
	}
}

func Test_DnstapProcessor_DecodeDNSCounters(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, "peertest", config.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// get dns packet
	responsePacket, _ := dnsutils.GetDNSResponsePacket()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(6) // CLIENT_RESPONSE
	dt.Message.ResponseMessage = responsePacket
	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 {
		t.Fatalf("expected message in batch")
	}
	dm := batch.Messages[0]
	if dm.DNS.QdCount != 1 {
		t.Errorf("invalid number of questions in dns message: got %d expect 1", dm.DNS.QdCount)
	}
	if dm.DNS.NsCount != 1 {
		t.Errorf("invalid number of nscount in dns message: got %d expect 1", dm.DNS.NsCount)
	}
	if dm.DNS.AnCount != 1 {
		t.Errorf("invalid number of ancount in dns message: got %d expect 1", dm.DNS.AnCount)
	}
	if dm.DNS.ArCount != 1 {
		t.Errorf("invalid number of arcount in dns message: got %d expect 1", dm.DNS.ArCount)
	}
}

func Test_DnstapProcessor_MalformedDnsHeader(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	// init the dnstap consumer
	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", config.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("www.google.fr.", dns.TypeA)
	dnsquestion, _ := dnsmsg.Pack()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion[:4]

	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_MalformedDnsQuestion(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	// init the dnstap consumer
	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", config.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsquestion := []byte{88, 27, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112,
		99, 111, 108, 108, 101, 99, 116, 111, 114, 4, 116, 101, 115, 116, 0}

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion

	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_MalformedDnsAnswer(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	// init the dnstap consumer
	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", config.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsanswer := []byte{46, 172, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 15, 100, 110, 115, 116, 97, 112, 99, 111, 108, 108, 101, 99, 116,
		111, 114, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 127, 0}

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(6)
	dt.Message.ResponseMessage = dnsanswer

	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_EmptyDnsPayload(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	// init the dnstap consumer
	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", config.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)

	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNS.MalformedPacket == true {
		t.Errorf("malformed packet detected, should not with empty payload")
	}
}

func Test_DnstapProcessor_DisableDNSParser(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	// init the dnstap consumer
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.DisableDNSParser = true

	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", cfg, logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("www.google.fr.", dns.TypeA)
	dnsquestion, _ := dnsmsg.Pack()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion

	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNS.ID != 0 {
		t.Errorf("DNS ID should be equal to zero: %v", batch.Messages)
	}
}

// test to decode the extended part
func Test_DnstapProcessor_Extended(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.ExtendedSupport = true

	consumer := NewDNSTapProcessor(0, "peertest", cfg, logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("www.google.fr.", dns.TypeA)
	dnsquestion, _ := dnsmsg.Pack()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion

	edt := &dnsutils.ExtendedDnstap{}
	edt.Atags = &dnsutils.ExtendedATags{
		Tags: []string{"atags:value"},
	}
	edt.OriginalDnstapExtra = []byte("originalextrafield")
	edt.Normalize = &dnsutils.ExtendedNormalize{
		Tld:         "org",
		EtldPlusOne: "dnscollector.org",
	}
	edt.Filtering = &dnsutils.ExtendedFiltering{
		SampleRate: 30,
	}
	edtData, _ := proto.Marshal(edt)
	dt.Extra = edtData

	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 {
		t.Fatalf("expected message in batch")
	}
	dm := batch.Messages[0]
	if dm.DNSTap.Extra != "originalextrafield" {
		t.Errorf("invalid extra field: %s", dm.DNSTap.Extra)
	}
	if dm.ATags.Tags[0] != "atags:value" {
		t.Errorf("invalid atags: %s", dm.ATags.Tags[0])
	}
	if dm.PublicSuffix.QnameEffectiveTLDPlusOne != "dnscollector.org" {
		t.Errorf("invalid etld+1: %s", dm.PublicSuffix.QnameEffectiveTLDPlusOne)
	}
	if dm.PublicSuffix.QnamePublicSuffix != "org" {
		t.Errorf("invalid tld: %s", dm.PublicSuffix.QnamePublicSuffix)
	}
	if dm.Filtering.SampleRate != 30 {
		t.Errorf("invalid sample rate: %d", dm.Filtering.SampleRate)
	}
}

// test for issue https://github.com/dmachard/go-dnscollector/v3/issues/568
func Test_DnstapProcessor_BufferLoggerIsFull(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferOne)

	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 512)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the dnstap consumer
	cfg := config.GetDefaultConfig()
	cfg.Global.Worker.BatchSize = 1
	cfg.Global.Worker.InternalMonitor = 1
	consumer := NewDNSTapProcessor(0, "peertest", cfg, lg, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion(config.ExpectedQname+".", dns.TypeA)
	dnsquestion, _ := dnsmsg.Pack()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5)
	dt.Message.QueryMessage = dnsquestion

	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packets to consumer
	for i := 0; i < 512; i++ {
		consumer.GetDataChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(config.ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNS.Qname != config.ExpectedQname {
		t.Errorf("invalid qname in dns message: %v", batch.Messages)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		consumer.GetDataChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(config.ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	batch2 := <-fl.GetInputChannel()
	if len(batch2.Messages) == 0 || batch2.Messages[0].DNS.Qname != config.ExpectedQname {
		t.Errorf("invalid qname in second dns message: %v", batch2.Messages)
	}
}

// test for telemetry counter
func Test_DnstapProcessor_TelemetryCounters(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// run the consumer with a fake logger
	fl := GetWorkerForTest(config.DefaultBufferSize)

	cfg := config.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = true
	cfg.Global.Worker.InternalMonitor = 1

	metrics := telemetry.NewPrometheusCollector(cfg)

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, "peertest", cfg, logger, "test", 512)
	consumer.SetMetrics(metrics)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// get dns packet
	queryPkt, _ := dnsutils.GetFakeDNS()

	// prepare dnstap
	dt := &dnstap.Dnstap{}
	dt.Type = dnstap.Dnstap_Type.Enum(1)

	dt.Message = &dnstap.Message{}
	dt.Message.Type = dnstap.Message_Type.Enum(5) // CLIENT_QUERY
	dt.Message.ResponseMessage = queryPkt
	data, _ := proto.Marshal(dt)

	// start the consumer
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packet to consumer and read output
	consumer.GetDataChannel() <- data

	<-fl.GetInputChannel()
	r := <-metrics.Record

	if r.TotalIngress != 1 {
		t.Errorf("invalid total ingress counter: got %d expect 1", r.TotalIngress)
	}
	if r.TotalEgress != 1 {
		t.Errorf("invalid total egress counter: got %d expect 1", r.TotalEgress)
	}
}

func Test_DnstapProcessor_RawBatch(t *testing.T) {
	fl := GetWorkerForTest(config.DefaultBufferSize)
	cfg := config.GetDefaultConfig()
	proc := NewDNSTapProcessor(0, "test", cfg, logger.New(false), "test", 1000)
	proc.SetDefaultRoutes([]Worker{fl})

	// Prepare dnstap frame
	queryPkt, err := dnsutils.GetFakeDNS()
	if err != nil {
		t.Fatalf("dns question pack error: %v", err)
	}
	dt := &dnstap.Dnstap{
		Type: dnstap.Dnstap_MESSAGE.Enum(),
		Message: &dnstap.Message{
			Type:         dnstap.Message_CLIENT_QUERY.Enum(),
			QueryMessage: queryPkt,
		},
	}
	data, _ := proto.Marshal(dt)

	go proc.StartCollect()
	defer proc.Stop()

	// Send RawBatch with 5 frames
	batch := dnsutils.AcquireRawBatch()
	for i := 0; i < 5; i++ {
		batch.Frames = append(batch.Frames, data)
	}
	proc.GetBatchChannel() <- batch

	// Read output batch
	select {
	case outBatch := <-fl.GetInputChannel():
		if len(outBatch.Messages) != 5 {
			t.Errorf("expected 5 messages in batch, got %d", len(outBatch.Messages))
		}
		if len(outBatch.Messages) > 0 && outBatch.Messages[0].DNSTap.Operation != "CLIENT_QUERY" {
			t.Errorf("unexpected operation: %s", outBatch.Messages[0].DNSTap.Operation)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for batch")
	}
}

func Test_DnstapCollector_LowTrafficFlush(t *testing.T) {
	fl := GetWorkerForTest(config.DefaultBufferSize)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.ListenPort = 6002
	cfg.Collectors.Dnstap.UpstreamBatching = true
	cfg.Global.Worker.ChannelBufferSize = 1000

	server := NewDnstapServer([]Worker{fl}, cfg, logger.New(false), "bench-server")
	go server.StartCollect()
	defer server.Stop()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", ":6002")
	if err != nil {
		t.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
	if err := fs.InitSender(); err != nil {
		t.Fatalf("framestream init error: %v", err)
	}

	queryPkt, err := dnsutils.GetFakeDNS()
	if err != nil {
		t.Fatalf("dns question pack error: %v", err)
	}
	dt := GetFakeDNSTap(queryPkt)
	data, _ := proto.Marshal(dt)
	frame := &framestream.Frame{}
	frame.Write(data)

	// Send only 3 frames (far below 256 batchSize) without closing connection
	for i := 0; i < 3; i++ {
		if err := fs.SendFrame(frame); err != nil {
			t.Fatalf("send frame error: %v", err)
		}
	}

	// Verify all 3 frames are flushed and received immediately (< 1s)
	received := 0
	for received < 3 {
		select {
		case b := <-fl.GetInputChannel():
			received += len(b.Messages)
		case <-time.After(1 * time.Second):
			t.Fatalf("timeout waiting for flushed frames, received %d/3", received)
		}
	}
}

func Test_Dnstap_PcapOutput_Regression_Issue1388(t *testing.T) {
	testWorker := GetWorkerForTest(config.DefaultBufferSize)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.ListenPort = 6003
	cfg.Global.Worker.ChannelBufferSize = 1000

	server := NewDnstapServer([]Worker{testWorker}, cfg, logger.New(false), "dnstap-pcap-test")
	go server.StartCollect()
	defer server.Stop()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", ":6003")
	if err != nil {
		t.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
	if err := fs.InitSender(); err != nil {
		t.Fatalf("framestream init error: %v", err)
	}

	dnsquery, err := dnsutils.GetFakeDNS()
	if err != nil {
		t.Fatalf("dns question pack error: %v", err)
	}

	// 1. Message with SocketFamily_INET
	dtINET := GetFakeDNSTap(dnsquery)
	dataINET, err := proto.Marshal(dtINET)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	frameINET := &framestream.Frame{}
	frameINET.Write(dataINET)
	if err := fs.SendFrame(frameINET); err != nil {
		t.Fatalf("send frame error: %v", err)
	}

	// 2. Message with SocketFamily omitted/not set (reproducing issue #1388 with IPv4 addresses)
	dtUnknown := GetFakeDNSTap(dnsquery)
	dtUnknown.GetMessage().SocketFamily = nil // omit socket family
	qIP := net.ParseIP("10.1.2.3").To4()
	rIP := net.ParseIP("10.3.4.5").To4()
	dtUnknown.GetMessage().QueryAddress = qIP
	dtUnknown.GetMessage().ResponseAddress = rIP
	dataUnknown, err := proto.Marshal(dtUnknown)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	frameUnknown := &framestream.Frame{}
	frameUnknown.Write(dataUnknown)
	if err := fs.SendFrame(frameUnknown); err != nil {
		t.Fatalf("send frame error: %v", err)
	}

	// 3. Message with SocketFamily_INET6
	dtINET6 := GetFakeDNSTap(dnsquery)
	sf6 := dnstap.SocketFamily_INET6
	dtINET6.GetMessage().SocketFamily = &sf6
	dtINET6.GetMessage().QueryAddress = net.ParseIP("2001:db8::1")
	dtINET6.GetMessage().ResponseAddress = net.ParseIP("2001:db8::2")
	dataINET6, err := proto.Marshal(dtINET6)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	frameINET6 := &framestream.Frame{}
	frameINET6.Write(dataINET6)
	if err := fs.SendFrame(frameINET6); err != nil {
		t.Fatalf("send frame error: %v", err)
	}

	// 4. Message with SocketFamily omitted but IPv6 addresses
	dtUnknown6 := GetFakeDNSTap(dnsquery)
	dtUnknown6.GetMessage().SocketFamily = nil
	dtUnknown6.GetMessage().QueryAddress = net.ParseIP("2001:db8::10")
	dtUnknown6.GetMessage().ResponseAddress = net.ParseIP("2001:db8::20")
	dataUnknown6, err := proto.Marshal(dtUnknown6)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	frameUnknown6 := &framestream.Frame{}
	frameUnknown6.Write(dataUnknown6)
	if err := fs.SendFrame(frameUnknown6); err != nil {
		t.Fatalf("send frame error: %v", err)
	}

	// Read all 4 messages from worker channel
	var messages []*dnsutils.DNSMessage
	for len(messages) < 4 {
		select {
		case batch := <-testWorker.GetInputChannel():
			messages = append(messages, batch.Messages...)
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for messages, got %d/4", len(messages))
		}
	}

	// Check 1: SocketFamily_INET message
	msg1 := messages[0]
	if msg1.NetworkInfo.Family != netutils.ProtoIPv4 {
		t.Errorf("case 1 (INET): expected family %q, got %q", netutils.ProtoIPv4, msg1.NetworkInfo.Family)
	}
	var buf1 [512]byte
	_, err = msg1.EncodeToPacketBytes(buf1[:0], true)
	if err != nil {
		t.Errorf("case 1 (INET): EncodeToPacketBytes failed: %v", err)
	}

	// Check 2: SocketFamily omitted IPv4 message
	msg2 := messages[1]
	if msg2.NetworkInfo.Family != netutils.ProtoIPv4 {
		t.Errorf("case 2 (omitted SocketFamily IPv4): expected family %q, got %q", netutils.ProtoIPv4, msg2.NetworkInfo.Family)
	}
	var buf2 [512]byte
	_, err = msg2.EncodeToPacketBytes(buf2[:0], true)
	if err != nil {
		t.Errorf("case 2 (omitted SocketFamily IPv4): EncodeToPacketBytes failed: %v", err)
	}

	// Check 3: SocketFamily_INET6 message
	msg3 := messages[2]
	if msg3.NetworkInfo.Family != netutils.ProtoIPv6 {
		t.Errorf("case 3 (INET6): expected family %q, got %q", netutils.ProtoIPv6, msg3.NetworkInfo.Family)
	}
	var buf3 [512]byte
	_, err = msg3.EncodeToPacketBytes(buf3[:0], true)
	if err != nil {
		t.Errorf("case 3 (INET6): EncodeToPacketBytes failed: %v", err)
	}

	// Check 4: SocketFamily omitted IPv6 message
	msg4 := messages[3]
	if msg4.NetworkInfo.Family != netutils.ProtoIPv6 {
		t.Errorf("case 4 (omitted SocketFamily IPv6): expected family %q, got %q", netutils.ProtoIPv6, msg4.NetworkInfo.Family)
	}
	var buf4 [512]byte
	_, err = msg4.EncodeToPacketBytes(buf4[:0], true)
	if err != nil {
		t.Errorf("case 4 (omitted SocketFamily IPv6): EncodeToPacketBytes failed: %v", err)
	}
}
