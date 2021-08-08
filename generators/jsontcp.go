package generators

import (
	"bufio"
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

type JsonTcpSender struct {
	done       chan bool
	channel    chan dnsutils.DnsMessage
	config     *dnsutils.Config
	logger     *logger.Logger
	exit       chan bool
	conn       net.Conn
	remoteIP   string
	remotePort int
	retry      int
}

func NewJsonTcpSender(config *dnsutils.Config, logger *logger.Logger) *JsonTcpSender {
	logger.Info("generator json tcp sender - enabled")
	s := &JsonTcpSender{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsutils.DnsMessage, 512),
		logger:  logger,
		config:  config,
	}

	s.ReadConfig()

	return s
}

func (o *JsonTcpSender) ReadConfig() {
	o.remoteIP = o.config.Generators.JsonTcp.RemoteIP
	o.remotePort = o.config.Generators.JsonTcp.RemotePort
	o.retry = o.config.Generators.JsonTcp.RetryInterval
}

func (o *JsonTcpSender) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("generator json tcp sender - "+msg, v...)
}

func (o *JsonTcpSender) LogError(msg string, v ...interface{}) {
	o.logger.Error("generator json tcp sender - "+msg, v...)
}

func (o *JsonTcpSender) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *JsonTcpSender) Stop() {
	o.LogInfo("stopping...")

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *JsonTcpSender) Run() {
	o.LogInfo("running in background...")

LOOP:
	for {
	LOOP_RECONNECT:
		for {
			select {
			case <-o.exit:
				break LOOP
			default:
				o.LogInfo("connecting to remote destination")
				conn, err := net.Dial("tcp", o.remoteIP+":"+strconv.Itoa(o.remotePort))
				if err != nil {
					o.LogError("connect error: %s", err)
				}
				if conn != nil {
					o.LogInfo("connected")
					o.conn = conn
					w := bufio.NewWriter(conn)
					for {
						select {
						case dm := <-o.channel:
							json.NewEncoder(w).Encode(dm)
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
				o.LogInfo("retry to connect in 5 seconds")
				time.Sleep(time.Duration(o.retry) * time.Second)
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
