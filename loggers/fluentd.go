package loggers

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/vmihailenco/msgpack"
)

type FluentdClient struct {
	done    chan bool
	channel chan dnsutils.DnsMessage
	config  *dnsutils.Config
	logger  *logger.Logger
	exit    chan bool
	conn    net.Conn
	name    string
}

func NewFluentdClient(config *dnsutils.Config, logger *logger.Logger, name string) *FluentdClient {
	logger.Info("[%s] logger to fluentd - enabled", name)
	s := &FluentdClient{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
		name:    name,
	}

	s.ReadConfig()

	return s
}

func (c *FluentdClient) GetName() string { return c.name }

func (c *FluentdClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *FluentdClient) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.Fluentd.TlsMinVersion) {
		o.logger.Fatal("logger fluentd - invalid tls min version")
	}
}

func (o *FluentdClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to fluentd - "+msg, v...)
}

func (o *FluentdClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to fluentd - "+msg, v...)
}

func (o *FluentdClient) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *FluentdClient) Stop() {
	o.LogInfo("stopping...")

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *FluentdClient) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name)

LOOP:
	for {
	LOOP_RECONNECT:
		for {
			select {
			case <-o.exit:
				break LOOP
			default:
				// prepare the address
				var address string
				if len(o.config.Loggers.Fluentd.SockPath) > 0 {
					address = o.config.Loggers.Fluentd.SockPath
				} else {
					address = o.config.Loggers.Fluentd.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.Fluentd.RemotePort)
				}

				// make the connection
				o.LogInfo("connecting to %s", address)
				//var conn net.Conn
				var err error
				if o.config.Loggers.Fluentd.TlsSupport {
					tlsConfig := &tls.Config{
						InsecureSkipVerify: false,
						MinVersion:         tls.VersionTLS12,
					}

					tlsConfig.InsecureSkipVerify = o.config.Loggers.Fluentd.TlsInsecure
					tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.Fluentd.TlsMinVersion]

					o.conn, err = tls.Dial(o.config.Loggers.Fluentd.Transport, address, tlsConfig)
				} else {
					o.conn, err = net.Dial(o.config.Loggers.Fluentd.Transport, address)
				}

				// something is wrong during connection ?
				if err != nil {
					o.LogError("connect error: %s", err)
				}

				// loop
				if o.conn != nil {
					o.LogInfo("connected")
					tag, _ := msgpack.Marshal(o.config.Loggers.Fluentd.Tag)
					for {
						select {
						case dm := <-o.channel:
							// apply tranforms
							if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
								continue
							}

							// prepare event
							tm, _ := msgpack.Marshal(dm.DnsTap.TimeSec)
							record, err := msgpack.Marshal(dm)
							if err != nil {
								o.LogError("msgpack error:", err.Error())
								continue
							}

							// Message ::= [ Tag, Time, Record, Option? ]
							encoded := []byte{}
							// array, size 3
							encoded = append(encoded, 0x93)
							// append tag, time and record
							encoded = append(encoded, tag...)
							encoded = append(encoded, tm...)
							encoded = append(encoded, record...)

							// write event message
							_, err = o.conn.Write(encoded)

							// flusth the buffer
							if err != nil {
								o.LogError("connection error:", err.Error())
								break LOOP_RECONNECT
							}
						case <-o.exit:
							o.logger.Info("closing loop...")
							break LOOP
						}
					}

				}
				o.LogInfo("retry to connect in %d seconds", o.config.Loggers.Fluentd.RetryInterval)
				time.Sleep(time.Duration(o.config.Loggers.Fluentd.RetryInterval) * time.Second)
			}
		}
	}

	if o.conn != nil {
		o.LogInfo("closing tcp connection")
		o.conn.Close()
	}

	o.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	o.done <- true
}
