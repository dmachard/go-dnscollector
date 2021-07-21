package generators

import (
	"bufio"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

type DnstapSender struct {
	done       chan bool
	channel    chan dnsmessage.DnsMessage
	config     *common.Config
	logger     *logger.Logger
	exit       chan bool
	conn       net.Conn
	remoteIP   string
	remotePort int
	identity   string
	retry      int
}

func NewDnstapSender(config *common.Config, logger *logger.Logger) *DnstapSender {
	logger.Info("generator dnstap sender - enabled")
	s := &DnstapSender{
		done:    make(chan bool),
		exit:    make(chan bool),
		channel: make(chan dnsmessage.DnsMessage, 512),
		logger:  logger,
	}

	s.ReadConfig()

	return s
}

func (o *DnstapSender) ReadConfig() {
	o.remoteIP = o.config.Generators.DnstapSender.RemoteIP
	o.remotePort = o.config.Generators.DnstapSender.RemotePort
	o.identity = o.config.Generators.DnstapSender.DnstapIdentity
	o.retry = o.config.Generators.DnstapSender.Retry
}

func (o *DnstapSender) Channel() chan dnsmessage.DnsMessage {
	return o.channel
}

func (o *DnstapSender) Stop() {
	o.logger.Info("generator dnstap sender - stopping...")

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *DnstapSender) Run() {
	o.logger.Info("generator dnstap sender - running in background...")

	dt := &dnstap.Dnstap{}
	frame := &framestream.Frame{}

LOOP:
	for {
	LOOP_RECONNET:
		for {
			select {
			case <-o.exit:
				break LOOP
			default:
				o.logger.Info("generator dnstap sender - connecting to remote destination")
				conn, err := net.Dial("tcp", o.remoteIP+":"+strconv.Itoa(o.remotePort))
				if err != nil {
					o.logger.Error("generator dnstap sender - connect error: %s", err)
				}
				if conn != nil {
					o.logger.Info("generator dnstap sender - connected with remote")
					o.conn = conn
					// frame stream library
					r := bufio.NewReader(conn)
					w := bufio.NewWriter(conn)
					fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

					// init framestream protocol
					if err := fs.InitSender(); err != nil {
						o.logger.Error("generator dnstap sender - sender protocol initialization error %s", err)
						break
					} else {
						o.logger.Info("generator dnstap sender - framestream initialized")
					}

					for {
						select {
						case dm := <-o.channel:

							dt.Reset()

							t := dnstap.Dnstap_MESSAGE
							dt.Identity = []byte(o.identity)
							dt.Version = []byte("-")
							dt.Type = &t

							mt := dnstap.Message_Type(dnstap.Message_Type_value[dm.Operation])
							sf := dnstap.SocketFamily(dnstap.SocketFamily_value[dm.Family])
							sp := dnstap.SocketProtocol(dnstap.SocketProtocol_value[dm.Protocol])
							tsec := uint64(dm.Timesec)
							tnsec := uint32(dm.Timensec)
							rportint, err := strconv.Atoi(dm.ResponsePort)
							if err != nil {
								o.logger.Error("output dnstap sender - error to encode dnstap response port %s", err)
								continue
							}
							rport := uint32(rportint)
							qportint, err := strconv.Atoi(dm.QueryPort)
							if err != nil {
								o.logger.Error("output dnstap sender - error to encode dnstap query port %s", err)
								continue
							}
							qport := uint32(qportint)

							msg := &dnstap.Message{Type: &mt}

							msg.SocketFamily = &sf
							msg.SocketProtocol = &sp
							msg.QueryAddress = net.ParseIP(dm.QueryIp)
							msg.QueryPort = &qport
							msg.ResponseAddress = net.ParseIP(dm.ResponseIp)
							msg.ResponsePort = &rport

							if dm.Type == "query" {
								msg.QueryMessage = dm.Payload
								msg.QueryTimeSec = &tsec
								msg.QueryTimeNsec = &tnsec
							} else {
								msg.ResponseTimeSec = &tsec
								msg.ResponseTimeNsec = &tnsec
								msg.ResponseMessage = dm.Payload
							}

							dt.Message = msg

							data, err := proto.Marshal(dt)
							if err != nil {
								o.logger.Error("generator dnstap sender - proto marshal error %s", err)
							}

							frame.Write(data)
							if err := fs.SendFrame(frame); err != nil {
								o.logger.Error("generator dnstap sender - send frame error %s", err)
								break LOOP_RECONNET
							}
						case <-o.exit:
							o.logger.Info("generator dnstap sender - closing framestream")
							if err = fs.ResetSender(); err != nil {
								o.logger.Error("generator dnstap sender - reset framestream error %s", err)
							}
							break LOOP
						}
					}

				}
				o.logger.Info("generator dnstap sender - retry to connect in 5 seconds")
				time.Sleep(time.Duration(o.retry) * time.Second)
			}
		}
	}

	if o.conn != nil {
		o.logger.Info("generator dnstap sender - closing tcp connection")
		o.conn.Close()
	}
	o.logger.Info("generator dnstap sender - run terminated")
	o.done <- true
}
