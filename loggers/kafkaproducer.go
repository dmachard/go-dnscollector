package loggers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

type KafkaProducer struct {
	done           chan bool
	channel        chan dnsutils.DnsMessage
	config         *dnsutils.Config
	logger         *logger.Logger
	exit           chan bool
	textFormat     []string
	name           string
	kafkaConn      *kafka.Conn
	kafkaReady     chan bool
	kafkaReconnect chan bool
	kafkaConnected bool
}

func NewKafkaProducer(config *dnsutils.Config, logger *logger.Logger, name string) *KafkaProducer {
	logger.Info("[%s] logger to kafka - enabled", name)
	s := &KafkaProducer{
		done:           make(chan bool),
		exit:           make(chan bool),
		channel:        make(chan dnsutils.DnsMessage, 512),
		logger:         logger,
		config:         config,
		kafkaReady:     make(chan bool),
		kafkaReconnect: make(chan bool),
		name:           name,
	}

	s.ReadConfig()

	return s
}

func (c *KafkaProducer) GetName() string { return c.name }

func (c *KafkaProducer) SetLoggers(loggers []dnsutils.Worker) {}

func (o *KafkaProducer) ReadConfig() {

	if o.config.Loggers.RedisPub.TlsSupport && !dnsutils.IsValidTLS(o.config.Loggers.RedisPub.TlsMinVersion) {
		o.logger.Fatal("logger to kafka - invalid tls min version")
	}

	if len(o.config.Loggers.RedisPub.TextFormat) > 0 {
		o.textFormat = strings.Fields(o.config.Loggers.RedisPub.TextFormat)
	} else {
		o.textFormat = strings.Fields(o.config.Global.TextFormat)
	}
}

func (o *KafkaProducer) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger to kafka - "+msg, v...)
}

func (o *KafkaProducer) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger to kafka - "+msg, v...)
}

func (o *KafkaProducer) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *KafkaProducer) Stop() {
	o.LogInfo("stopping...")

	// exit to close properly
	o.exit <- true

	// read done channel and block until run is terminated
	<-o.done
	close(o.done)
}

func (o *KafkaProducer) Disconnect() {
	if o.kafkaConn != nil {
		o.LogInfo("closing  connection")
		o.kafkaConn.Close()
	}
}

func (o *KafkaProducer) ConnectToKafka(ctx context.Context, readyTimer *time.Timer) {
	for {
		readyTimer.Reset(time.Duration(10) * time.Second)

		if o.kafkaConn != nil {
			o.kafkaConn.Close()
			o.kafkaConn = nil
		}

		topic := o.config.Loggers.KafkaProducer.Topic
		partition := o.config.Loggers.KafkaProducer.Partition
		address := o.config.Loggers.KafkaProducer.RemoteAddress + ":" + strconv.Itoa(o.config.Loggers.KafkaProducer.RemotePort)

		o.LogInfo("connecting to kafka=%s partition=%d topic=%s", address, partition, topic)

		dialer := &kafka.Dialer{
			Timeout:   time.Duration(o.config.Loggers.KafkaProducer.ConnectTimeout) * time.Second,
			Deadline:  time.Now().Add(5 * time.Second),
			DualStack: true,
		}

		// enable TLS
		if o.config.Loggers.KafkaProducer.TlsSupport {
			tlsConfig := &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			}
			tlsConfig.InsecureSkipVerify = o.config.Loggers.TcpClient.TlsInsecure
			tlsConfig.MinVersion = dnsutils.TLS_VERSION[o.config.Loggers.TcpClient.TlsMinVersion]

			dialer.TLS = tlsConfig
		}

		// SASL Support
		if o.config.Loggers.KafkaProducer.SaslSupport {
			switch o.config.Loggers.KafkaProducer.SaslMechanism {
			case dnsutils.SASL_MECHANISM_PLAIN:
				mechanism := plain.Mechanism{
					Username: o.config.Loggers.KafkaProducer.SaslUsername,
					Password: o.config.Loggers.KafkaProducer.SaslPassword,
				}
				dialer.SASLMechanism = mechanism
			case dnsutils.SASL_MECHANISM_SCRAM:
				mechanism, err := scram.Mechanism(
					scram.SHA512,
					o.config.Loggers.KafkaProducer.SaslUsername,
					o.config.Loggers.KafkaProducer.SaslPassword,
				)
				if err != nil {
					panic(err)
				}
				dialer.SASLMechanism = mechanism
			}

		}

		conn, err := dialer.DialLeader(ctx, "tcp", address, topic, partition)
		if err != nil {
			o.LogError("%s", err)
			o.LogInfo("retry to connect in %d seconds", o.config.Loggers.KafkaProducer.RetryInterval)
			time.Sleep(time.Duration(o.config.Loggers.KafkaProducer.RetryInterval) * time.Second)
			continue
		}

		o.kafkaConn = conn

		// block until is ready
		o.kafkaReady <- true
		o.kafkaReconnect <- true
	}
}

func (o *KafkaProducer) FlushBuffer(buf *[]dnsutils.DnsMessage) {
	msgs := []kafka.Message{}
	buffer := new(bytes.Buffer)
	strDm := ""

	for _, dm := range *buf {
		switch o.config.Loggers.KafkaProducer.Mode {
		case dnsutils.MODE_TEXT:
			strDm = dm.String(o.textFormat, o.config.Global.TextFormatDelimiter, o.config.Global.TextFormatBoundary)
		case dnsutils.MODE_JSON:
			json.NewEncoder(buffer).Encode(dm)
			strDm = buffer.String()
			buffer.Reset()
		case dnsutils.MODE_FLATJSON:
			flat, err := dm.Flatten()
			if err != nil {
				o.LogError("flattening DNS message failed: %e", err)
			}
			json.NewEncoder(buffer).Encode(flat)
			strDm = buffer.String()
			buffer.Reset()
		}

		msg := kafka.Message{
			Key:   []byte(dm.DnsTap.Identity),
			Value: []byte(strDm),
		}
		msgs = append(msgs, msg)

	}

	_, err := o.kafkaConn.WriteMessages(msgs...)
	if err != nil {
		o.LogError("failed to write message", err.Error())
		o.kafkaConnected = false
		<-o.kafkaReconnect
	}

	// reset buffer
	*buf = nil
}

func (o *KafkaProducer) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.channel)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel)

	ctx, cancelKafka := context.WithCancel(context.Background())
	defer cancelKafka() // Libérez les ressources liées au contexte

	// init buffer
	bufferDm := []dnsutils.DnsMessage{}

	// init flust timer for buffer
	readyTimer := time.NewTimer(time.Duration(10) * time.Second)

	// init flust timer for buffer
	flushInterval := time.Duration(o.config.Loggers.KafkaProducer.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	go o.ConnectToKafka(ctx, readyTimer)

LOOP:
	for {
		select {
		case <-o.exit:
			o.LogInfo("closing loop...")
			break LOOP

		case <-readyTimer.C:
			o.LogError("failed to established connection")
			cancelKafka()

		case <-o.kafkaReady:
			o.LogInfo("connected with success")
			readyTimer.Stop()
			o.kafkaConnected = true

		case dm := <-o.channel:
			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !o.kafkaConnected {
				continue
			}

			// apply tranforms
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= o.config.Loggers.KafkaProducer.BufferSize {
				o.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !o.kafkaConnected {
				o.LogInfo("buffer cleared!")
				bufferDm = nil
				continue
			}

			if len(bufferDm) > 0 {
				o.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}

	o.LogInfo("run terminated")

	// cleanup transformers
	subprocessors.Reset()

	// closing kafka connection if exist
	o.Disconnect()

	o.done <- true
}
