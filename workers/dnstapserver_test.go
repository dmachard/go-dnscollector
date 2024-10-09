package workers

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/telemetry"
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
			g := GetWorkerForTest(pkgconfig.DefaultBufferSize)

			config := pkgconfig.GetDefaultConfig()
			if tc.listenPort > 0 {
				config.Collectors.Dnstap.ListenPort = tc.listenPort
			}
			if tc.mode == netutils.SocketUnix {
				config.Collectors.Dnstap.SockPath = tc.address
			}
			config.Collectors.Dnstap.Compression = tc.compression

			// start the collector
			c := NewDnstapServer([]Worker{g}, config, logger.New(false), "test")
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

				if config.Collectors.Dnstap.Compression == pkgconfig.CompressNone {
					// send the frame
					bulkFrame.Write(data)
					if err := fs.SendFrame(bulkFrame); err != nil {
						t.Fatalf("send frame error %s", err)
					}
				} else {
					subFrame.Write(data)
					bulkFrame.AppendData(subFrame.Data())
				}

				if config.Collectors.Dnstap.Compression != pkgconfig.CompressNone {
					bulkFrame.Encode()
					if err := fs.SendCompressedFrame(&compress.GzipCodec, bulkFrame); err != nil {
						t.Fatalf("send compressed frame error %s", err)
					}
				}
			}

			// waiting message in channel
			msg := <-g.GetInputChannel()
			if msg.DNSTap.Operation != tc.operation {
				t.Errorf("want %s, got %s", tc.operation, msg.DNSTap.Operation)
			}

			c.Stop()
		})
	}
}

// Testcase for https://github.com/dmachard/go-dnscollector/issues/461
// Support Bind9 with dnstap closing.
func Test_DnstapCollector_CloseFrameStream(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 50)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	config := pkgconfig.GetDefaultConfig()
	config.Collectors.Dnstap.SockPath = "/tmp/dnscollector.sock"

	// start the collector in unix mode
	g := GetWorkerForTest(pkgconfig.DefaultBufferSize)
	c := NewDnstapServer([]Worker{g}, config, lg, "test")
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

	regxp := ".*framestream reseted by sender.*"
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
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, "peertest", pkgconfig.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion(pkgconfig.ExpectedQname+".", dns.TypeA)
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

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}
}

func Test_DnstapProcessor_DecodeDNSCounters(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, "peertest", pkgconfig.GetDefaultConfig(), logger, "test", 512)
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

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
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
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// init the dnstap consumer
	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", pkgconfig.GetDefaultConfig(), logger, "test", 512)
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

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_MalformedDnsQuestion(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// init the dnstap consumer
	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", pkgconfig.GetDefaultConfig(), logger, "test", 512)
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

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_MalformedDnsAnswer(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// init the dnstap consumer
	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", pkgconfig.GetDefaultConfig(), logger, "test", 512)
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

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.MalformedPacket == false {
		t.Errorf("malformed packet not detected")
	}
}

func Test_DnstapProcessor_EmptyDnsPayload(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// init the dnstap consumer
	logger := logger.New(false)
	consumer := NewDNSTapProcessor(0, "peertest", pkgconfig.GetDefaultConfig(), logger, "test", 512)
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

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.MalformedPacket == true {
		t.Errorf("malformed packet detected, should not with empty payload")
	}
}

func Test_DnstapProcessor_DisableDNSParser(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// init the dnstap consumer
	cfg := pkgconfig.GetDefaultConfig()
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

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.ID != 0 {
		t.Errorf("DNS ID should be equal to zero: %d", dm.DNS.ID)
	}
}

// test to decode the extended part
func Test_DnstapProcessor_Extended(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init the dnstap consumer
	cfg := pkgconfig.GetDefaultConfig()
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

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
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

// test for issue https://github.com/dmachard/go-dnscollector/issues/568
func Test_DnstapProcessor_BufferLoggerIsFull(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferOne)

	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 30)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the dnstap consumer
	consumer := NewDNSTapProcessor(0, "peertest", pkgconfig.GetDefaultConfig(), lg, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dns query
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion(pkgconfig.ExpectedQname+".", dns.TypeA)
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

	// add packets to consumer
	for i := 0; i < 512; i++ {
		consumer.GetDataChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	dm := <-fl.GetInputChannel()
	if dm.DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in dns message: %s", dm.DNS.Qname)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		consumer.GetDataChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	dm2 := <-fl.GetInputChannel()
	if dm2.DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in second dns message: %s", dm2.DNS.Qname)
	}
}

// test for telemetry counter
func Test_DnstapProcessor_TelemetryCounters(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	cfg := pkgconfig.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = true
	cfg.Global.Worker.InternalMonitor = 1

	config := pkgconfig.Config{}
	metrics := telemetry.NewPrometheusCollector(&config)

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

	// add packet to consumer and read output
	consumer.GetDataChannel() <- data

	<-fl.GetInputChannel()
	r := <-metrics.Record

	if r.TotalIngress != 1 {
		t.Errorf("invalid total ingress oucnter: got %d expect 1", r.TotalIngress)
	}
	if r.TotalEgress != 1 {
		t.Errorf("invalid total egress counter: got %d expect 1", r.TotalEgress)
	}
}
