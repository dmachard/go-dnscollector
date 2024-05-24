package workers

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/dmachard/go-topmap"
)

type StatsPerStream struct {
	TotalPackets, TotalSentBytes, TotalReceivedBytes               int
	Clients, Domains, Nxdomains                                    map[string]int
	RRtypes, Rcodes, Operations, Transports, IPproto               map[string]int
	TopRcodes, TopOperations, TopIPproto, TopTransport, TopRRtypes *topmap.TopMap
}

type StreamStats struct {
	Streams map[string]*StatsPerStream
}

type StatsdClient struct {
	*GenericWorker
	Stats StreamStats
	sync.RWMutex
}

func NewStatsdClient(config *pkgconfig.Config, logger *logger.Logger, name string) *StatsdClient {
	w := &StatsdClient{GenericWorker: NewGenericWorker(config, logger, name, "statsd", config.Loggers.Statsd.ChannelBufferSize, pkgconfig.DefaultMonitor)}
	w.Stats = StreamStats{Streams: make(map[string]*StatsPerStream)}
	w.ReadConfig()
	return w
}

func (w *StatsdClient) ReadConfig() {
	if !netutils.IsValidTLS(w.GetConfig().Loggers.Statsd.TLSMinVersion) {
		w.LogFatal(pkgconfig.PrefixLogWorker + "[" + w.GetName() + "]statd - invalid tls min version")
	}
}

func (w *StatsdClient) RecordDNSMessage(dm dnsutils.DNSMessage) {
	w.Lock()
	defer w.Unlock()

	// add stream
	if _, exists := w.Stats.Streams[dm.DNSTap.Identity]; !exists {
		w.Stats.Streams[dm.DNSTap.Identity] = &StatsPerStream{
			Clients: make(map[string]int), Domains: make(map[string]int), Nxdomains: make(map[string]int),
			RRtypes: make(map[string]int), Rcodes: make(map[string]int), Operations: make(map[string]int), Transports: make(map[string]int), IPproto: make(map[string]int),
			TopRcodes: topmap.NewTopMap(50), TopOperations: topmap.NewTopMap(50), TopIPproto: topmap.NewTopMap(50), TopRRtypes: topmap.NewTopMap(50), TopTransport: topmap.NewTopMap(50),
			TotalPackets: 0, TotalSentBytes: 0, TotalReceivedBytes: 0,
		}
	}

	// global number of packets
	w.Stats.Streams[dm.DNSTap.Identity].TotalPackets++

	if dm.DNS.Type == dnsutils.DNSQuery {
		w.Stats.Streams[dm.DNSTap.Identity].TotalReceivedBytes += dm.DNS.Length
	} else {
		w.Stats.Streams[dm.DNSTap.Identity].TotalSentBytes += dm.DNS.Length
	}

	// count client and domains
	if _, exists := w.Stats.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname]; !exists {
		w.Stats.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname] = 1
	} else {
		w.Stats.Streams[dm.DNSTap.Identity].Domains[dm.DNS.Qname] += 1
	}
	if dm.DNS.Rcode == dnsutils.DNSRcodeNXDomain {
		if _, exists := w.Stats.Streams[dm.DNSTap.Identity].Nxdomains[dm.DNS.Qname]; !exists {
			w.Stats.Streams[dm.DNSTap.Identity].Nxdomains[dm.DNS.Qname] = 1
		} else {
			w.Stats.Streams[dm.DNSTap.Identity].Nxdomains[dm.DNS.Qname] += 1
		}
	}
	if _, exists := w.Stats.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP]; !exists {
		w.Stats.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP] = 1
	} else {
		w.Stats.Streams[dm.DNSTap.Identity].Clients[dm.NetworkInfo.QueryIP] += 1
	}

	// record ip proto
	if _, ok := w.Stats.Streams[dm.DNSTap.Identity].IPproto[dm.NetworkInfo.Family]; !ok {
		w.Stats.Streams[dm.DNSTap.Identity].IPproto[dm.NetworkInfo.Family] = 1
	} else {
		w.Stats.Streams[dm.DNSTap.Identity].IPproto[dm.NetworkInfo.Family]++
	}
	w.Stats.Streams[dm.DNSTap.Identity].TopIPproto.Record(
		dm.NetworkInfo.Family,
		w.Stats.Streams[dm.DNSTap.Identity].IPproto[dm.NetworkInfo.Family],
	)

	// record transports
	if _, ok := w.Stats.Streams[dm.DNSTap.Identity].Transports[dm.NetworkInfo.Protocol]; !ok {
		w.Stats.Streams[dm.DNSTap.Identity].Transports[dm.NetworkInfo.Protocol] = 1
	} else {
		w.Stats.Streams[dm.DNSTap.Identity].Transports[dm.NetworkInfo.Protocol]++
	}
	w.Stats.Streams[dm.DNSTap.Identity].TopTransport.Record(
		dm.NetworkInfo.Protocol,
		w.Stats.Streams[dm.DNSTap.Identity].Transports[dm.NetworkInfo.Protocol],
	)

	// record rrtypes
	if _, ok := w.Stats.Streams[dm.DNSTap.Identity].RRtypes[dm.DNS.Qtype]; !ok {
		w.Stats.Streams[dm.DNSTap.Identity].RRtypes[dm.DNS.Qtype] = 1
	} else {
		w.Stats.Streams[dm.DNSTap.Identity].RRtypes[dm.DNS.Qtype]++
	}
	w.Stats.Streams[dm.DNSTap.Identity].TopRRtypes.Record(
		dm.DNS.Qtype,
		w.Stats.Streams[dm.DNSTap.Identity].RRtypes[dm.DNS.Qtype],
	)

	// record rcodes
	if _, ok := w.Stats.Streams[dm.DNSTap.Identity].Rcodes[dm.DNS.Rcode]; !ok {
		w.Stats.Streams[dm.DNSTap.Identity].Rcodes[dm.DNS.Rcode] = 1
	} else {
		w.Stats.Streams[dm.DNSTap.Identity].Rcodes[dm.DNS.Rcode]++
	}
	w.Stats.Streams[dm.DNSTap.Identity].TopRcodes.Record(
		dm.DNS.Rcode,
		w.Stats.Streams[dm.DNSTap.Identity].Rcodes[dm.DNS.Rcode],
	)

	// record operations
	if _, ok := w.Stats.Streams[dm.DNSTap.Identity].Operations[dm.DNSTap.Operation]; !ok {
		w.Stats.Streams[dm.DNSTap.Identity].Operations[dm.DNSTap.Operation] = 1
	} else {
		w.Stats.Streams[dm.DNSTap.Identity].Operations[dm.DNSTap.Operation]++
	}
	w.Stats.Streams[dm.DNSTap.Identity].TopOperations.Record(
		dm.DNSTap.Operation,
		w.Stats.Streams[dm.DNSTap.Identity].Operations[dm.DNSTap.Operation],
	)
}

func (w *StatsdClient) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

			// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *StatsdClient) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	// statd timer to push data
	t2Interval := time.Duration(w.GetConfig().Loggers.Statsd.FlushInterval) * time.Second
	t2 := time.NewTimer(t2Interval)

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// record the dnstap message
			w.RecordDNSMessage(dm)

		case <-t2.C:
			address := w.GetConfig().Loggers.Statsd.RemoteAddress + ":" + strconv.Itoa(w.GetConfig().Loggers.Statsd.RemotePort)
			connTimeout := time.Duration(w.GetConfig().Loggers.Statsd.ConnectTimeout) * time.Second

			// make the connection
			var conn net.Conn
			var err error

			switch w.GetConfig().Loggers.Statsd.Transport {
			case netutils.SocketTCP, netutils.SocketUDP:
				w.LogInfo("connecting to %s://%s", w.GetConfig().Loggers.Statsd.Transport, address)
				conn, err = net.DialTimeout(w.GetConfig().Loggers.Statsd.Transport, address, connTimeout)

			case netutils.SocketTLS:
				w.LogInfo("connecting to %s://%s", w.GetConfig().Loggers.Statsd.Transport, address)

				var tlsConfig *tls.Config

				tlsOptions := netutils.TLSOptions{
					InsecureSkipVerify: w.GetConfig().Loggers.Statsd.TLSInsecure,
					MinVersion:         w.GetConfig().Loggers.Statsd.TLSMinVersion,
					CAFile:             w.GetConfig().Loggers.Statsd.CAFile,
					CertFile:           w.GetConfig().Loggers.Statsd.CertFile,
					KeyFile:            w.GetConfig().Loggers.Statsd.KeyFile,
				}

				tlsConfig, err = netutils.TLSClientConfig(tlsOptions)
				if err == nil {
					dialer := &net.Dialer{Timeout: connTimeout}
					conn, err = tls.DialWithDialer(dialer, netutils.SocketTCP, address, tlsConfig)
				}
			default:
				w.LogFatal("logger=statsd - invalid transport:", w.GetConfig().Loggers.Statsd.Transport)
			}

			// something is wrong during connection ?
			if err != nil {
				w.LogError("dial error: %s", err)
			}

			if conn != nil {
				w.LogInfo("dialing with success, continue...")

				b := bufio.NewWriter(conn)

				prefix := w.GetConfig().Loggers.Statsd.Prefix
				for streamID, stream := range w.Stats.Streams {
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
					w.LogError("sent data error:", err.Error())
				}
			}

			// reset the timer
			t2.Reset(t2Interval)
		}
	}
}
