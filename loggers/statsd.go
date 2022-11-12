package loggers

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type StatsdClient struct {
	done    chan bool
	channel chan dnsutils.DnsMessage
	config  *dnsutils.Config
	logger  *logger.Logger
	stats   *StatsStreams
	exit    chan bool
	version string
	name    string
}

func NewStatsdClient(config *dnsutils.Config, logger *logger.Logger, version string, name string) *StatsdClient {
	logger.Info("[%s] logger to statsd - enabled", name)

	s := &StatsdClient{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
		version: version,
		name:    name,
	}

	// check config
	s.ReadConfig()

	// init engine to compute statistics
	s.stats = NewStreamsStats(config, version, 0)

	return s
}

func (c *StatsdClient) GetName() string { return c.name }

func (c *StatsdClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *StatsdClient) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.Statsd.TlsMinVersion) {
		o.logger.Fatal("logger statd - invalid tls min version")
	}
}

func (o *StatsdClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to statsd - "+msg, v...)
}

func (o *StatsdClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to statsd - "+msg, v...)
}

func (o *StatsdClient) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *StatsdClient) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *StatsdClient) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	transformsConfig := (*dnsutils.ConfigTransformers)(&o.config.OutgoingTransformers)
	subprocessors := transformers.NewTransforms(transformsConfig, o.logger, o.name)

	// init timer to compute qps
	t1_interval := 1 * time.Second
	t1 := time.NewTimer(t1_interval)

	// statd timer to push data
	t2_interval := time.Duration(o.config.Loggers.Statsd.FlushInterval) * time.Second
	t2 := time.NewTimer(t2_interval)

LOOP:
	for {
		select {

		case dm, opened := <-o.channel:
			if !opened {
				o.LogInfo("channel closed")
				break LOOP
			}

			// apply tranforms
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// record the dnstap message
			o.stats.Record(dm)

		case <-t1.C:
			// compute qps each second
			o.stats.Compute()

			// reset the timer
			t1.Reset(t1_interval)

		case <-t2.C:
			address := o.config.Loggers.Statsd.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.Statsd.RemotePort)

			// make the connection
			o.LogInfo("dial to %s", address)
			var conn net.Conn
			var err error
			if o.config.Loggers.Statsd.TlsSupport {
				tlsConfig := &tls.Config{
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: false,
				}
				tlsConfig.InsecureSkipVerify = o.config.Loggers.Statsd.TlsInsecure
				tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.Statsd.TlsMinVersion]

				conn, err = tls.Dial(o.config.Loggers.Statsd.Transport, address, tlsConfig)
			} else {
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
				for _, stream := range o.stats.Streams() {
					counters := o.stats.GetCounters(stream)
					totalClients := o.stats.GetTotalClients(stream)
					totalDomains := o.stats.GetTotalDomains(stream)
					totalNxdomains := o.stats.GetTotalNxdomains(stream)

					topRcodes := o.stats.GetTopRcodes(stream)
					topRrtypes := o.stats.GetTopRrtypes(stream)
					topTransports := o.stats.GetTopTransports(stream)
					topIpProto := o.stats.GetTopIpProto(stream)

					b.WriteString(fmt.Sprintf("%s_%s_total_bytes_received:%d|c\n", prefix, stream, counters.ReceivedBytesTotal))
					b.WriteString(fmt.Sprintf("%s_%s_total_bytes_sent:%d|c\n", prefix, stream, counters.SentBytesTotal))

					b.WriteString(fmt.Sprintf("%s_%s_total_requesters:%d|c\n", prefix, stream, totalClients))

					b.WriteString(fmt.Sprintf("%s_%s_total_domains:%d|c\n", prefix, stream, totalDomains))
					b.WriteString(fmt.Sprintf("%s_%s_total_domains_nx:%d|c\n", prefix, stream, totalNxdomains))

					b.WriteString(fmt.Sprintf("%s_%s_total_packets:%d|c\n", prefix, stream, counters.Packets))

					// transport repartition
					for _, v := range topTransports {
						b.WriteString(fmt.Sprintf("%s_%s_total_packets_%s:%d|c\n", prefix, stream, v.Name, v.Hit))
					}

					// ip proto repartition
					for _, v := range topIpProto {
						b.WriteString(fmt.Sprintf("%s_%s_total_packets_%s:%d|c\n", prefix, stream, v.Name, v.Hit))
					}

					// qtypes repartition
					for _, v := range topRrtypes {
						b.WriteString(fmt.Sprintf("%s_%s_total_replies_rrtype_%s:%d|c\n", prefix, stream, v.Name, v.Hit))
					}

					// top rcodes
					for _, v := range topRcodes {
						b.WriteString(fmt.Sprintf("%s_%s_total_replies_rcode_%s:%d|c\n", prefix, stream, v.Name, v.Hit))
					}

					b.WriteString(fmt.Sprintf("%s_%s_queries_qps:%d|g\n", prefix, stream, counters.Qps))
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

	o.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// the job is done
	o.done <- true
}
