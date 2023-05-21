package loggers

import (
	"crypto/tls"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"

	influxdb2 "github.com/influxdata/influxdb-client-go"
	"github.com/influxdata/influxdb-client-go/api"
)

type InfluxDBClient struct {
	done         chan bool
	channel      chan dnsutils.DnsMessage
	config       *dnsutils.Config
	logger       *logger.Logger
	influxdbConn influxdb2.Client
	writeAPI     api.WriteAPI
	cleanup      chan bool
	name         string
}

func NewInfluxDBClient(config *dnsutils.Config, logger *logger.Logger, name string) *InfluxDBClient {
	logger.Info("[%s] logger to influxdb - enabled", name)

	s := &InfluxDBClient{
		done:    make(chan bool),
		cleanup: make(chan bool),
		channel: make(chan dnsutils.DnsMessage, config.Loggers.InfluxDB.ChannelBufferSize),
		logger:  logger,
		config:  config,
		name:    name,
	}

	s.ReadConfig()

	return s
}

func (c *InfluxDBClient) GetName() string { return c.name }

func (c *InfluxDBClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *InfluxDBClient) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.InfluxDB.TlsMinVersion) {
		o.logger.Fatal("logger influxdb - invalid tls min version")
	}
}

func (o *InfluxDBClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to influxdb - "+msg, v...)
}

func (o *InfluxDBClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to influxdb - "+msg, v...)
}

func (o *InfluxDBClient) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *InfluxDBClient) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	o.cleanup <- true

	// read done channel and block until run is terminated
	<-o.done
	o.LogInfo("run terminated")
	close(o.done)
}

func (o *InfluxDBClient) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.channel)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel)

	// prepare options for influxdb
	opts := influxdb2.DefaultOptions()
	opts.SetUseGZip(true)
	if o.config.Loggers.InfluxDB.TlsSupport {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		}

		tlsConfig.InsecureSkipVerify = o.config.Loggers.InfluxDB.TlsInsecure
		tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.InfluxDB.TlsMinVersion]

		opts.SetTLSConfig(tlsConfig)
	}
	// init the client
	influxClient := influxdb2.NewClientWithOptions(
		o.config.Loggers.InfluxDB.ServerURL,
		o.config.Loggers.InfluxDB.AuthToken,
		opts,
	)

	writeAPI := influxClient.WriteAPI(
		o.config.Loggers.InfluxDB.Organization,
		o.config.Loggers.InfluxDB.Bucket,
	)

	o.influxdbConn = influxClient
	o.writeAPI = writeAPI
	for {
		select {
		case <-o.cleanup:
			o.LogInfo("cleanup called")
			close(o.channel)

			// Force all unwritten data to be sent
			o.writeAPI.Flush()
			// Ensures background processes finishes
			o.influxdbConn.Close()

			// cleanup transformers
			subprocessors.Reset()

			o.done <- true
			return
		case dm, opened := <-o.channel:
			// channel is closed ?
			if !opened {
				o.LogInfo("channel closed, cleanup...")
				o.cleanup <- true
				continue
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDnsMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			p := influxdb2.NewPointWithMeasurement("dns").
				AddTag("Identity", dm.DnsTap.Identity).
				AddTag("QueryIP", dm.NetworkInfo.QueryIp).
				AddTag("Qname", dm.DNS.Qname).
				AddField("Operation", dm.DnsTap.Operation).
				AddField("Family", dm.NetworkInfo.Family).
				AddField("Protocol", dm.NetworkInfo.Protocol).
				AddField("Qtype", dm.DNS.Qtype).
				AddField("Rcode", dm.DNS.Rcode).
				SetTime(time.Unix(int64(dm.DnsTap.TimeSec), int64(dm.DnsTap.TimeNsec)))

			// write asynchronously
			o.writeAPI.WritePoint(p)
		}

	}
}
