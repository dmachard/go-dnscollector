package loggers

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
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
}

func NewFluentdClient(config *dnsutils.Config, logger *logger.Logger) *FluentdClient {
	logger.Info("logger to fluentd - enabled")
	s := &FluentdClient{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
	}

	s.ReadConfig()

	return s
}

func (o *FluentdClient) ReadConfig() {
	//tbc
}

func (o *FluentdClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("logger to fluentd - "+msg, v...)
}

func (o *FluentdClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("logger to fluentd - "+msg, v...)
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
					conf := &tls.Config{
						InsecureSkipVerify: o.config.Loggers.Fluentd.TlsInsecure,
					}
					o.conn, err = tls.Dial(o.config.Loggers.Fluentd.Transport, address, conf)
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
	o.done <- true
}
