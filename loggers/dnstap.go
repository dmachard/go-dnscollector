package loggers

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

type DnstapSender struct {
	done    chan bool
	channel chan dnsutils.DnsMessage
	config  *dnsutils.Config
	logger  *logger.Logger
	exit    chan bool
	conn    net.Conn
	name    string
}

func NewDnstapSender(config *dnsutils.Config, logger *logger.Logger, name string) *DnstapSender {
	logger.Info("logger dnstap [%s] sender - enabled", name)
	s := &DnstapSender{
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

func (c *DnstapSender) GetName() string { return c.name }

func (c *DnstapSender) SetLoggers(loggers []dnsutils.Worker) {
}

func (o *DnstapSender) ReadConfig() {
	// get hostname

	if o.config.Loggers.Dnstap.ServerId == "" {
		o.config.Loggers.Dnstap.ServerId = o.config.GetServerIdentity()
	}

	if !dnsutils.IsValidTLS(o.config.Loggers.Dnstap.TlsMinVersion) {
		o.logger.Fatal("logger dnstap - invalid tls min version")
	}
}

func (o *DnstapSender) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("logger dnstap sender - "+msg, v...)
}

func (o *DnstapSender) LogError(msg string, v ...interface{}) {
	o.logger.Error("logger dnstap sender - "+msg, v...)
}

func (o *DnstapSender) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *DnstapSender) Stop() {
	o.LogInfo("stopping...")

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *DnstapSender) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	transformsConfig := (*dnsutils.ConfigTransformers)(&o.config.OutgoingTransformers)
	subprocessors := transformers.NewTransforms(transformsConfig, o.logger, o.name)

	dt := &dnstap.Dnstap{}
	frame := &framestream.Frame{}

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
				var transport string
				if len(o.config.Loggers.Dnstap.SockPath) > 0 {
					address = o.config.Loggers.Dnstap.SockPath
					transport = "unix"
				} else {
					address = o.config.Loggers.Dnstap.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.Dnstap.RemotePort)
					transport = dnsutils.SOCKET_TCP
				}

				// make the connection
				o.LogInfo("connecting to %s", address)
				var conn net.Conn
				var err error
				if o.config.Loggers.Dnstap.TlsSupport {
					tlsConfig := &tls.Config{
						InsecureSkipVerify: false,
						MinVersion:         tls.VersionTLS12,
					}
					tlsConfig.InsecureSkipVerify = o.config.Loggers.Dnstap.TlsInsecure
					tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.Dnstap.TlsMinVersion]

					conn, err = tls.Dial(transport, address, tlsConfig)
				} else {
					conn, err = net.Dial(transport, address)
				}

				// something is wrong during connection ?
				if err != nil {
					o.LogError("connect error: %s", err)
				}

				if conn != nil {
					o.LogInfo("connected with remote")
					o.conn = conn
					// frame stream library
					r := bufio.NewReader(conn)
					w := bufio.NewWriter(conn)
					fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

					// init framestream protocol
					if err := fs.InitSender(); err != nil {
						o.LogError("sender protocol initialization error %s", err)
						break
					} else {
						o.LogInfo("framestream initialized")
					}

					for {
						select {
						case dm := <-o.channel:

							// apply tranforms
							if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
								continue
							}

							dt.Reset()

							t := dnstap.Dnstap_MESSAGE
							dt.Identity = []byte(o.config.Loggers.Dnstap.ServerId)
							dt.Version = []byte("-")
							dt.Type = &t

							mt := dnstap.Message_Type(dnstap.Message_Type_value[dm.DnsTap.Operation])
							sf := dnstap.SocketFamily(dnstap.SocketFamily_value[dm.NetworkInfo.Family])
							sp := dnstap.SocketProtocol(dnstap.SocketProtocol_value[dm.NetworkInfo.Protocol])
							tsec := uint64(dm.DnsTap.TimeSec)
							tnsec := uint32(dm.DnsTap.TimeNsec)

							var rportint int
							var qportint int

							// no response port provided ?
							// fix for issue #110
							if dm.NetworkInfo.ResponsePort == "-" {
								rportint = 0
							} else {
								rportint, err = strconv.Atoi(dm.NetworkInfo.ResponsePort)
								if err != nil {
									o.LogError("error to encode dnstap response port %s", err)
									continue
								}
							}
							rport := uint32(rportint)

							// no query port provided ?
							// fix to prevent issue #110
							if dm.NetworkInfo.QueryPort == "-" {
								qportint = 0
							} else {
								qportint, err = strconv.Atoi(dm.NetworkInfo.QueryPort)
								if err != nil {
									o.LogError("error to encode dnstap query port %s", err)
									continue
								}
							}
							qport := uint32(qportint)

							msg := &dnstap.Message{Type: &mt}

							msg.SocketFamily = &sf
							msg.SocketProtocol = &sp
							msg.QueryAddress = net.ParseIP(dm.NetworkInfo.QueryIp)
							msg.QueryPort = &qport
							msg.ResponseAddress = net.ParseIP(dm.NetworkInfo.ResponseIp)
							msg.ResponsePort = &rport

							if dm.DNS.Type == dnsutils.DnsQuery {
								msg.QueryMessage = dm.DNS.Payload
								msg.QueryTimeSec = &tsec
								msg.QueryTimeNsec = &tnsec
							} else {
								msg.ResponseTimeSec = &tsec
								msg.ResponseTimeNsec = &tnsec
								msg.ResponseMessage = dm.DNS.Payload
							}

							dt.Message = msg

							data, err := proto.Marshal(dt)
							if err != nil {
								o.LogError("proto marshal error %s", err)
							}

							frame.Write(data)
							if err := fs.SendFrame(frame); err != nil {
								o.LogError("send frame error %s", err)
								break LOOP_RECONNECT
							}
						case <-o.exit:
							o.logger.Info("closing framestream")
							if err = fs.ResetSender(); err != nil {
								o.LogError("reset framestream error %s", err)
							}
							break LOOP
						}
					}

				}
				o.LogInfo("retry to connect in 5 seconds")
				time.Sleep(time.Duration(o.config.Loggers.Dnstap.RetryInterval) * time.Second)
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
