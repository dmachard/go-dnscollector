package loggers

import (
	"crypto/tls"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
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
	exit         chan bool
}

func NewInfluxDBClient(config *dnsutils.Config, logger *logger.Logger) *InfluxDBClient {
	logger.Info("logger to influxdb - enabled")

	s := &InfluxDBClient{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
	}

	s.ReadConfig()

	return s
}

func (o *InfluxDBClient) ReadConfig() {
	//tbc
}

func (o *InfluxDBClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("logger to influxdb - "+msg, v...)
}

func (o *InfluxDBClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("logger to influxdb - "+msg, v...)
}

func (o *InfluxDBClient) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *InfluxDBClient) Stop() {
	o.LogInfo("stopping...")

	// close output channel
	o.LogInfo("closing channel")
	close(o.channel)

	// Force all unwritten data to be sent
	o.writeAPI.Flush()
	// Ensures background processes finishes
	o.influxdbConn.Close()

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *InfluxDBClient) Run() {
	o.LogInfo("running in background...")

	// prepare options for influxdb
	opts := influxdb2.DefaultOptions()
	opts.SetUseGZip(true)
	if o.config.Loggers.InfluxDB.TlsSupport {
		tlsconf := &tls.Config{
			InsecureSkipVerify: o.config.Loggers.InfluxDB.TlsInsecure,
		}
		opts.SetTLSConfig(tlsconf)
	}
	// init the client
	influxClient := influxdb2.NewClientWithOptions(o.config.Loggers.InfluxDB.ServerURL,
		o.config.Loggers.InfluxDB.AuthToken, opts)

	writeAPI := influxClient.WriteAPI(o.config.Loggers.InfluxDB.Organization,
		o.config.Loggers.InfluxDB.Bucket)

	o.influxdbConn = influxClient
	o.writeAPI = writeAPI
	for dm := range o.channel {
		p := influxdb2.NewPointWithMeasurement("dns").
			AddTag("Identity", dm.Identity).
			AddTag("QueryIP", dm.QueryIp).
			AddTag("Qname", dm.Qname).
			AddField("Operation", dm.Operation).
			AddField("Family", dm.Family).
			AddField("Protocol", dm.Protocol).
			AddField("Qtype", dm.Qtype).
			AddField("Rcode", dm.Rcode).
			SetTime(time.Unix(int64(dm.TimeSec), int64(dm.TimeNsec)))

		// write asynchronously
		o.writeAPI.WritePoint(p)
	}

	o.LogInfo("run terminated")
	// the job is done
	o.done <- true
}
