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
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
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
	inputChan   chan dnsutils.DNSMessage
	outputChan  chan dnsutils.DNSMessage
	config      *pkgconfig.Config
	configChan  chan *pkgconfig.Config
	logger      *logger.Logger
	name        string

	Stats StreamStats
	sync.RWMutex
}

func NewStatsdClient(config *pkgconfig.Config, logger *logger.Logger, name string) *StatsdClient {
	logger.Info("[%s] logger=statsd - enabled", name)

	s := &StatsdClient{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DNSMessage, config.Loggers.Statsd.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DNSMessage, config.Loggers.Statsd.ChannelBufferSize),
		logger:      logger,
		config:      config,
		configChan:  make(chan *pkgconfig.Config),
		name:        name,
		Stats:       StreamStats{Streams: make(map[string]*StatsPerStream)},
	}

	// check config
	s.ReadConfig()

	return s
}

func (c *StatsdClient) GetName() string { return c.name }

func (c *StatsdClient) AddDroppedRoute(wrk dnsutils.Worker) {}

func (c *StatsdClient) AddDefaultRoute(wrk dnsutils.Worker) {}

func (c *StatsdClient) SetLoggers(loggers []dnsutils.Worker) {}

func (c *StatsdClient) ReadConfig() {
	if !pkgconfig.IsValidTLS(c.config.Loggers.Statsd.TLSMinVersion) {
		c.logger.Fatal("logger=statd - invalid tls min version")
	}
}

func (c *StatsdClient) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *StatsdClient) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=statsd - "+msg, v...)
}

func (c *StatsdClient) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=statsd - "+msg, v...)
}

func (c *StatsdClient) Channel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *StatsdClient) Stop() {
	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess
}

func (c *StatsdClient) RecordDNSMessage(dm dnsutils.DNSMessage) {
	c.Lock()
	defer c.Unlock()

	// add stream
	if _, exists := c.Stats.Streams[dm.DNSTap.Identity]; !exists {
		c.Stats.Streams[dm.DNSTap.Identity] = &StatsPerStream{
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
	c.Stats.Streams[dm.DNSTap.Identity].TotalPackets++

	if dm.DNS.Type == dnsutils.DNSQuery {
		c.Stats.Streams[dm.DNSTap.Identity].TotalReceivedBytes += dm.DNS.Length
	} else {
		c.Stats.Streams[dm.DNSTap.Identity].TotalSentBytes += dm.DNS.Length
	}

	// count client and domains
	if _, exists := c.Stats.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname]; !exists {
		c.Stats.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname] = 1
	} else {
		c.Stats.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname] += 1
	}
	if dm.DNS.Rcode == dnsutils.DNSRcodeNXDomain {
		if _, exists := c.Stats.Streams[dm.DNSTap.Identity].Nxdomains[dm.DNS.Qname]; !exists {
			c.Stats.Streams[dm.DNSTap.Identity].Nxdomains[dm.DNS.Qname] = 1
		} else {
			c.Stats.Streams[dm.DNSTap.Identity].Nxdomains[dm.DNS.Qname] += 1
		}
	}
	if _, exists := c.Stats.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP]; !exists {
		c.Stats.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP] = 1
	} else {
		c.Stats.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP] += 1
	}

	// record ip proto
	if _, ok := c.Stats.Streams[dm.DNSTap.Identity].IPproto[dm.NetworkInfo.Family]; !ok {
		c.Stats.Streams[dm.DNSTap.Identity].IPproto[dm.NetworkInfo.Family] = 1
	} else {
		c.Stats.Streams[dm.DNSTap.Identity].IPproto[dm.NetworkInfo.Family]++
	}
	c.Stats.Streams[dm.DNSTap.Identity].TopIPproto.Record(
		dm.NetworkInfo.Family,
		c.Stats.Streams[dm.DNSTap.Identity].IPproto[dm.NetworkInfo.Family],
	)

	// record transports
	if _, ok := c.Stats.Streams[dm.DNSTap.Identity].Transports[dm.NetworkInfo.Protocol]; !ok {
		c.Stats.Streams[dm.DNSTap.Identity].Transports[dm.NetworkInfo.Protocol] = 1
	} else {
		c.Stats.Streams[dm.DNSTap.Identity].Transports[dm.NetworkInfo.Protocol]++
	}
	c.Stats.Streams[dm.DNSTap.Identity].TopTransport.Record(
		dm.NetworkInfo.Protocol,
		c.Stats.Streams[dm.DNSTap.Identity].Transports[dm.NetworkInfo.Protocol],
	)

	// record rrtypes
	if _, ok := c.Stats.Streams[dm.DNSTap.Identity].RRtypes[dm.DNS.Qtype]; !ok {
		c.Stats.Streams[dm.DNSTap.Identity].RRtypes[dm.DNS.Qtype] = 1
	} else {
		c.Stats.Streams[dm.DNSTap.Identity].RRtypes[dm.DNS.Qtype]++
	}
	c.Stats.Streams[dm.DNSTap.Identity].TopRRtypes.Record(
		dm.DNS.Qtype,
		c.Stats.Streams[dm.DNSTap.Identity].RRtypes[dm.DNS.Qtype],
	)

	// record rcodes
	if _, ok := c.Stats.Streams[dm.DNSTap.Identity].Rcodes[dm.DNS.Rcode]; !ok {
		c.Stats.Streams[dm.DNSTap.Identity].Rcodes[dm.DNS.Rcode] = 1
	} else {
		c.Stats.Streams[dm.DNSTap.Identity].Rcodes[dm.DNS.Rcode]++
	}
	c.Stats.Streams[dm.DNSTap.Identity].TopRcodes.Record(
		dm.DNS.Rcode,
		c.Stats.Streams[dm.DNSTap.Identity].Rcodes[dm.DNS.Rcode],
	)

	// record operations
	if _, ok := c.Stats.Streams[dm.DNSTap.Identity].Operations[dm.DNSTap.Operation]; !ok {
		c.Stats.Streams[dm.DNSTap.Identity].Operations[dm.DNSTap.Operation] = 1
	} else {
		c.Stats.Streams[dm.DNSTap.Identity].Operations[dm.DNSTap.Operation]++
	}
	c.Stats.Streams[dm.DNSTap.Identity].TopOperations.Record(
		dm.DNSTap.Operation,
		c.Stats.Streams[dm.DNSTap.Identity].Operations[dm.DNSTap.Operation],
	)
}

func (c *StatsdClient) Run() {
	c.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, c.outputChan)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go c.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-c.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			c.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-c.configChan:
			if !opened {
				return
			}
			c.config = cfg
			c.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-c.inputChan:
			if !opened {
				c.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// send to output channel
			c.outputChan <- dm
		}
	}
	c.LogInfo("run terminated")
}

func (c *StatsdClient) Process() {
	// statd timer to push data
	t2Interval := time.Duration(c.config.Loggers.Statsd.FlushInterval) * time.Second
	t2 := time.NewTimer(t2Interval)

	c.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-c.stopProcess:
			c.doneProcess <- true
			break PROCESS_LOOP
		// incoming dns message to process
		case dm, opened := <-c.outputChan:
			if !opened {
				c.LogInfo("output channel closed!")
				return
			}

			// record the dnstap message
			c.RecordDNSMessage(dm)

		case <-t2.C:
			address := c.config.Loggers.Statsd.RemoteAddress + ":" + strconv.Itoa(c.config.Loggers.Statsd.RemotePort)
			connTimeout := time.Duration(c.config.Loggers.Statsd.ConnectTimeout) * time.Second

			// make the connection
			var conn net.Conn
			var err error

			switch c.config.Loggers.Statsd.Transport {
			case netlib.SocketTCP, netlib.SocketUDP:
				c.LogInfo("connecting to %s://%s", c.config.Loggers.Statsd.Transport, address)
				conn, err = net.DialTimeout(c.config.Loggers.Statsd.Transport, address, connTimeout)

			case netlib.SocketTLS:
				c.LogInfo("connecting to %s://%s", c.config.Loggers.Statsd.Transport, address)

				var tlsConfig *tls.Config

				tlsOptions := pkgconfig.TLSOptions{
					InsecureSkipVerify: c.config.Loggers.Statsd.TLSInsecure,
					MinVersion:         c.config.Loggers.Statsd.TLSMinVersion,
					CAFile:             c.config.Loggers.Statsd.CAFile,
					CertFile:           c.config.Loggers.Statsd.CertFile,
					KeyFile:            c.config.Loggers.Statsd.KeyFile,
				}

				tlsConfig, err = pkgconfig.TLSClientConfig(tlsOptions)
				if err == nil {
					dialer := &net.Dialer{Timeout: connTimeout}
					conn, err = tls.DialWithDialer(dialer, netlib.SocketTCP, address, tlsConfig)
				}
			default:
				c.logger.Fatal("logger=statsd - invalid transport:", c.config.Loggers.Statsd.Transport)
			}

			// something is wrong during connection ?
			if err != nil {
				c.LogError("dial error: %s", err)
			}

			if conn != nil {
				c.LogInfo("dialing with success, continue...")

				b := bufio.NewWriter(conn)

				prefix := c.config.Loggers.Statsd.Prefix
				for streamID, stream := range c.Stats.Streams {
					b.WriteString(fmt.Sprintf("%s_%s_total_bytes_received:%d|c\n", prefix, streamID, stream.TotalReceivedBytes))
					b.WriteString(fmt.Sprintf("%s_%s_total_bytes_sent:%d|c\n", prefix, streamID, stream.TotalSentBytes))

					b.WriteString(fmt.Sprintf("%s_%s_total_requesters:%d|c\n", prefix, streamID, len(stream.Clients)))

					b.WriteString(fmt.Sprintf("%s_%s_total_domains:%d|c\n", prefix, streamID, len(stream.Domains)))
					b.WriteString(fmt.Sprintf("%s_%s_total_domains_nx:%d|c\n", prefix, streamID, len(stream.Nxdomains)))

					b.WriteString(fmt.Sprintf("%s_%s_total_packets:%d|c\n", prefix, streamID, stream.TotalPackets))

					// transport repartition
					for _, v := range stream.TopTransport.Get() {
						b.WriteString(fmt.Sprintf("%s_%s_total_packets_%s:%d|c\n", prefix, streamID, v.Name, v.Hit))
					}

					// ip proto repartition
					for _, v := range stream.TopIPproto.Get() {
						b.WriteString(fmt.Sprintf("%s_%s_total_packets_%s:%d|c\n", prefix, streamID, v.Name, v.Hit))
					}

					// qtypes repartition
					for _, v := range stream.TopRRtypes.Get() {
						b.WriteString(fmt.Sprintf("%s_%s_total_replies_rrtype_%s:%d|c\n", prefix, streamID, v.Name, v.Hit))
					}

					// top rcodes
					for _, v := range stream.TopRcodes.Get() {
						b.WriteString(fmt.Sprintf("%s_%s_total_replies_rcode_%s:%d|c\n", prefix, streamID, v.Name, v.Hit))
					}
				}

				// send data
				err = b.Flush()
				if err != nil {
					c.LogError("sent data error:", err.Error())
				}
			}

			// reset the timer
			t2.Reset(t2Interval)
		}
	}
	c.LogInfo("processing terminated")
}
