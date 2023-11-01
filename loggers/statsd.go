package loggers

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-topmap"
)

type StatsPerStream struct {
	TotalPackets       int
	TotalSentBytes     int
	TotalReceivedBytes int

	Clients   map[string]int
	Domains   map[string]int
	Nxdomains map[string]int

	RRtypes    map[string]int
	Rcodes     map[string]int
	Operations map[string]int
	Transports map[string]int
	IPproto    map[string]int

	TopRcodes     *topmap.TopMap
	TopOperations *topmap.TopMap
	TopIPproto    *topmap.TopMap
	TopTransport  *topmap.TopMap
	TopRRtypes    *topmap.TopMap
}

type StreamStats struct {
	Streams map[string]*StatsPerStream
}

type StatsdClient struct {
	stopProcess chan bool
	doneProcess chan bool
	stopRun     chan bool
	doneRun     chan bool
	inputChan   chan dnsutils.DnsMessage
	outputChan  chan dnsutils.DnsMessage
	config      *dnsutils.Config
	configChan  chan *dnsutils.Config
	logger      *logger.Logger
	name        string

	Stats StreamStats
	sync.RWMutex
}

func NewStatsdClient(config *dnsutils.Config, logger *logger.Logger, name string) *StatsdClient {
	logger.Info("[%s] logger=statsd - enabled", name)

	s := &StatsdClient{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DnsMessage, config.Loggers.Statsd.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DnsMessage, config.Loggers.Statsd.ChannelBufferSize),
		logger:      logger,
		config:      config,
		configChan:  make(chan *dnsutils.Config),
		name:        name,
		Stats:       StreamStats{Streams: make(map[string]*StatsPerStream)},
	}

	// check config
	s.ReadConfig()

	return s
}

func (c *StatsdClient) GetName() string { return c.name }

func (c *StatsdClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *StatsdClient) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.Statsd.TlsMinVersion) {
		o.logger.Fatal("logger=statd - invalid tls min version")
	}
}

func (o *StatsdClient) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload configuration!")
	o.configChan <- config
}

func (o *StatsdClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger=statsd - "+msg, v...)
}

func (o *StatsdClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger=statsd - "+msg, v...)
}

func (o *StatsdClient) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *StatsdClient) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *StatsdClient) RecordDnsMessage(dm dnsutils.DnsMessage) {
	o.Lock()
	defer o.Unlock()

	// add stream
	if _, exists := o.Stats.Streams[dm.DnsTap.Identity]; !exists {
		o.Stats.Streams[dm.DnsTap.Identity] = &StatsPerStream{
			Clients:   make(map[string]int),
			Domains:   make(map[string]int),
			Nxdomains: make(map[string]int),

			RRtypes:    make(map[string]int),
			Rcodes:     make(map[string]int),
			Operations: make(map[string]int),
			Transports: make(map[string]int),
			IPproto:    make(map[string]int),

			TopRcodes:     topmap.NewTopMap(50),
			TopOperations: topmap.NewTopMap(50),
			TopIPproto:    topmap.NewTopMap(50),
			TopRRtypes:    topmap.NewTopMap(50),
			TopTransport:  topmap.NewTopMap(50),

			TotalPackets:       0,
			TotalSentBytes:     0,
			TotalReceivedBytes: 0,
		}
	}

	// global number of packets
	o.Stats.Streams[dm.DnsTap.Identity].TotalPackets++

	if dm.DNS.Type == dnsutils.DnsQuery {
		o.Stats.Streams[dm.DnsTap.Identity].TotalReceivedBytes += dm.DNS.Length
	} else {
		o.Stats.Streams[dm.DnsTap.Identity].TotalSentBytes += dm.DNS.Length
	}

	// count client and domains
	if _, exists := o.Stats.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname]; !exists {
		o.Stats.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname] = 1
	} else {
		o.Stats.Streams[dm.DnsTap.Identity].Domains[dm.DNS.Qname] += 1
	}
	if dm.DNS.Rcode == dnsutils.DNS_RCODE_NXDOMAIN {
		if _, exists := o.Stats.Streams[dm.DnsTap.Identity].Nxdomains[dm.DNS.Qname]; !exists {
			o.Stats.Streams[dm.DnsTap.Identity].Nxdomains[dm.DNS.Qname] = 1
		} else {
			o.Stats.Streams[dm.DnsTap.Identity].Nxdomains[dm.DNS.Qname] += 1
		}
	}
	if _, exists := o.Stats.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp]; !exists {
		o.Stats.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp] = 1
	} else {
		o.Stats.Streams[dm.DnsTap.Identity].Clients[dm.NetworkInfo.QueryIp] += 1
	}

	// record ip proto
	if _, ok := o.Stats.Streams[dm.DnsTap.Identity].IPproto[dm.NetworkInfo.Family]; !ok {
		o.Stats.Streams[dm.DnsTap.Identity].IPproto[dm.NetworkInfo.Family] = 1
	} else {
		o.Stats.Streams[dm.DnsTap.Identity].IPproto[dm.NetworkInfo.Family]++
	}
	o.Stats.Streams[dm.DnsTap.Identity].TopIPproto.Record(
		dm.NetworkInfo.Family,
		o.Stats.Streams[dm.DnsTap.Identity].IPproto[dm.NetworkInfo.Family],
	)

	// record transports
	if _, ok := o.Stats.Streams[dm.DnsTap.Identity].Transports[dm.NetworkInfo.Protocol]; !ok {
		o.Stats.Streams[dm.DnsTap.Identity].Transports[dm.NetworkInfo.Protocol] = 1
	} else {
		o.Stats.Streams[dm.DnsTap.Identity].Transports[dm.NetworkInfo.Protocol]++
	}
	o.Stats.Streams[dm.DnsTap.Identity].TopTransport.Record(
		dm.NetworkInfo.Protocol,
		o.Stats.Streams[dm.DnsTap.Identity].Transports[dm.NetworkInfo.Protocol],
	)

	// record rrtypes
	if _, ok := o.Stats.Streams[dm.DnsTap.Identity].RRtypes[dm.DNS.Qtype]; !ok {
		o.Stats.Streams[dm.DnsTap.Identity].RRtypes[dm.DNS.Qtype] = 1
	} else {
		o.Stats.Streams[dm.DnsTap.Identity].RRtypes[dm.DNS.Qtype]++
	}
	o.Stats.Streams[dm.DnsTap.Identity].TopRRtypes.Record(
		dm.DNS.Qtype,
		o.Stats.Streams[dm.DnsTap.Identity].RRtypes[dm.DNS.Qtype],
	)

	// record rcodes
	if _, ok := o.Stats.Streams[dm.DnsTap.Identity].Rcodes[dm.DNS.Rcode]; !ok {
		o.Stats.Streams[dm.DnsTap.Identity].Rcodes[dm.DNS.Rcode] = 1
	} else {
		o.Stats.Streams[dm.DnsTap.Identity].Rcodes[dm.DNS.Rcode]++
	}
	o.Stats.Streams[dm.DnsTap.Identity].TopRcodes.Record(
		dm.DNS.Rcode,
		o.Stats.Streams[dm.DnsTap.Identity].Rcodes[dm.DNS.Rcode],
	)

	// record operations
	if _, ok := o.Stats.Streams[dm.DnsTap.Identity].Operations[dm.DnsTap.Operation]; !ok {
		o.Stats.Streams[dm.DnsTap.Identity].Operations[dm.DnsTap.Operation] = 1
	} else {
		o.Stats.Streams[dm.DnsTap.Identity].Operations[dm.DnsTap.Operation]++
	}
	o.Stats.Streams[dm.DnsTap.Identity].TopOperations.Record(
		dm.DnsTap.Operation,
		o.Stats.Streams[dm.DnsTap.Identity].Operations[dm.DnsTap.Operation],
	)
}

func (o *StatsdClient) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.outputChan)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go o.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-o.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			o.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-o.configChan:
			if !opened {
				return
			}
			o.config = cfg
			o.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-o.inputChan:
			if !opened {
				o.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDnsMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// send to output channel
			o.outputChan <- dm
		}
	}
	o.LogInfo("run terminated")
}

func (o *StatsdClient) Process() {
	// statd timer to push data
	t2_interval := time.Duration(o.config.Loggers.Statsd.FlushInterval) * time.Second
	t2 := time.NewTimer(t2_interval)

	o.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			o.doneProcess <- true
			break PROCESS_LOOP
		// incoming dns message to process
		case dm, opened := <-o.outputChan:
			if !opened {
				o.LogInfo("output channel closed!")
				return
			}

			// record the dnstap message
			o.RecordDnsMessage(dm)

		case <-t2.C:
			address := o.config.Loggers.Statsd.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.Statsd.RemotePort)

			// make the connection
			var conn net.Conn
			var err error
			if o.config.Loggers.Statsd.TlsSupport {
				o.LogInfo("dial to tls://%s", address)
				tlsConfig := &tls.Config{
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: false,
				}
				tlsConfig.InsecureSkipVerify = o.config.Loggers.Statsd.TlsInsecure
				tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.Statsd.TlsMinVersion]

				conn, err = tls.Dial(o.config.Loggers.Statsd.Transport, address, tlsConfig)
			} else {
				o.LogInfo("dial to %s://%s", o.config.Loggers.Statsd.Transport, address)
				conn, err = net.Dial(o.config.Loggers.Statsd.Transport, address)
			}

			// something is wrong during connection ?
			if err != nil {
				o.LogError("dial error: %s", err)
			}

			if conn != nil {
				o.LogInfo("dialing with success, continue...")

				//var b bytes.Buffer
				b := bufio.NewWriter(conn)

				prefix := o.config.Loggers.Statsd.Prefix
				for streamId, stream := range o.Stats.Streams {
					b.WriteString(fmt.Sprintf("%s_%s_total_bytes_received:%d|c\n", prefix, streamId, stream.TotalReceivedBytes))
					b.WriteString(fmt.Sprintf("%s_%s_total_bytes_sent:%d|c\n", prefix, streamId, stream.TotalSentBytes))

					b.WriteString(fmt.Sprintf("%s_%s_total_requesters:%d|c\n", prefix, streamId, len(stream.Clients)))

					b.WriteString(fmt.Sprintf("%s_%s_total_domains:%d|c\n", prefix, streamId, len(stream.Domains)))
					b.WriteString(fmt.Sprintf("%s_%s_total_domains_nx:%d|c\n", prefix, streamId, len(stream.Nxdomains)))

					b.WriteString(fmt.Sprintf("%s_%s_total_packets:%d|c\n", prefix, streamId, stream.TotalPackets))

					// transport repartition
					for _, v := range stream.TopTransport.Get() {
						b.WriteString(fmt.Sprintf("%s_%s_total_packets_%s:%d|c\n", prefix, streamId, v.Name, v.Hit))
					}

					// ip proto repartition
					for _, v := range stream.TopIPproto.Get() {
						b.WriteString(fmt.Sprintf("%s_%s_total_packets_%s:%d|c\n", prefix, streamId, v.Name, v.Hit))
					}

					// qtypes repartition
					for _, v := range stream.TopRRtypes.Get() {
						b.WriteString(fmt.Sprintf("%s_%s_total_replies_rrtype_%s:%d|c\n", prefix, streamId, v.Name, v.Hit))
					}

					// top rcodes
					for _, v := range stream.TopRcodes.Get() {
						b.WriteString(fmt.Sprintf("%s_%s_total_replies_rcode_%s:%d|c\n", prefix, streamId, v.Name, v.Hit))
					}
				}

				// send data
				err = b.Flush()
				if err != nil {
					o.LogError("sent data error:", err.Error())
				}
			}

			// reset the timer
			t2.Reset(t2_interval)
		}
	}
	o.LogInfo("processing terminated")
}
