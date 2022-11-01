package loggers

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type TcpClient struct {
	done       chan bool
	channel    chan dnsutils.DnsMessage
	config     *dnsutils.Config
	logger     *logger.Logger
	exit       chan bool
	conn       net.Conn
	textFormat []string
	name       string
}

func NewTcpClient(config *dnsutils.Config, logger *logger.Logger, name string) *TcpClient {
	logger.Info("[%s] logger to tcp client - enabled", name)
	s := &TcpClient{
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

func (c *TcpClient) GetName() string { return c.name }

func (c *TcpClient) SetLoggers(loggers []dnsutils.Worker) {}

func (o *TcpClient) ReadConfig() {
	if !dnsutils.IsValidTLS(o.config.Loggers.TcpClient.TlsMinVersion) {
		o.logger.Fatal("logger tcp - invalid tls min version")
	}

	if len(o.config.Loggers.TcpClient.TextFormat) > 0 {
		o.textFormat = strings.Fields(o.config.Loggers.TcpClient.TextFormat)
	} else {
		o.textFormat = strings.Fields(o.config.Global.TextFormat)
	}
}

func (o *TcpClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to tcp client - "+msg, v...)
}

func (o *TcpClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to tcp client - "+msg, v...)
}

func (o *TcpClient) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *TcpClient) Stop() {
	o.LogInfo("stopping...")

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *TcpClient) Run() {
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
				if len(o.config.Loggers.TcpClient.SockPath) > 0 {
					address = o.config.Loggers.TcpClient.SockPath
				} else {
					address = o.config.Loggers.TcpClient.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.TcpClient.RemotePort)
				}

				// make the connection
				o.LogInfo("connecting to %s", address)
				var conn net.Conn
				var err error
				if o.config.Loggers.TcpClient.TlsSupport {
					tlsConfig := &tls.Config{
						MinVersion:         tls.VersionTLS12,
						InsecureSkipVerify: false,
					}
					tlsConfig.InsecureSkipVerify = o.config.Loggers.TcpClient.TlsInsecure
					tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.TcpClient.TlsMinVersion]

					conn, err = tls.Dial(o.config.Loggers.TcpClient.Transport, address, tlsConfig)
				} else {
					conn, err = net.Dial(o.config.Loggers.TcpClient.Transport, address)
				}

				// something is wrong during connection ?
				if err != nil {
					o.LogError("connect error: %s", err)
				}

				// loop
				if conn != nil {
					o.LogInfo("connected")
					o.conn = conn
					w := bufio.NewWriter(conn)
					for {
						select {
						case dm := <-o.channel:

							if o.config.Loggers.TcpClient.Mode == dnsutils.MODE_TEXT {
								w.Write(dm.Bytes(o.textFormat, o.config.Loggers.TcpClient.Delimiter))
							}

							if o.config.Loggers.TcpClient.Mode == dnsutils.MODE_JSON {
								json.NewEncoder(w).Encode(dm)
								w.WriteString(o.config.Loggers.TcpClient.Delimiter)
							}

							// flusth the buffer
							err = w.Flush()
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
				o.LogInfo("retry to connect in %d seconds", o.config.Loggers.TcpClient.RetryInterval)
				time.Sleep(time.Duration(o.config.Loggers.TcpClient.RetryInterval) * time.Second)
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
