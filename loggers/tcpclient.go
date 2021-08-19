package loggers

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/vmihailenco/msgpack"
)

type TcpClient struct {
	done    chan bool
	channel chan dnsutils.DnsMessage
	config  *dnsutils.Config
	logger  *logger.Logger
	exit    chan bool
	conn    net.Conn
}

func NewTcpClient(config *dnsutils.Config, logger *logger.Logger) *TcpClient {
	logger.Info("logger to tcp client - enabled")
	s := &TcpClient{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
	}

	s.ReadConfig()

	return s
}

func (o *TcpClient) ReadConfig() {
	//tbc
}

func (o *TcpClient) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("logger to tcp client - "+msg, v...)
}

func (o *TcpClient) LogError(msg string, v ...interface{}) {
	o.logger.Error("logger to tcp client - "+msg, v...)
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
					conf := &tls.Config{
						InsecureSkipVerify: o.config.Loggers.TcpClient.TlsInsecure,
					}
					conn, err = tls.Dial(o.config.Loggers.TcpClient.Transport, address, conf)
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

							if o.config.Loggers.TcpClient.Mode == "text" {
								w.Write(dm.Bytes())
							}

							if o.config.Loggers.TcpClient.Mode == "msgpack" {
								tag, _ := msgpack.Marshal("dns.collector")
								tm, _ := msgpack.Marshal(dm.Timestamp)
								record, _ := msgpack.Marshal(dm)

								encoded := []byte{0x93}
								encoded = append(encoded, tag...)
								encoded = append(encoded, tm...)
								encoded = append(encoded, record...)

								w.Write(encoded)
							}

							if o.config.Loggers.TcpClient.Mode == "json" {
								json.NewEncoder(w).Encode(dm)
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
