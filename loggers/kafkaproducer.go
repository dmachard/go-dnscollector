package loggers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

type KafkaProducer struct {
	stopProcess    chan bool
	doneProcess    chan bool
	stopRun        chan bool
	doneRun        chan bool
	inputChan      chan dnsutils.DNSMessage
	outputChan     chan dnsutils.DNSMessage
	config         *pkgconfig.Config
	configChan     chan *pkgconfig.Config
	logger         *logger.Logger
	textFormat     []string
	name           string
	kafkaConn      *kafka.Conn
	kafkaReady     chan bool
	kafkaReconnect chan bool
	kafkaConnected bool
	compressCodec  compress.Codec
}

func NewKafkaProducer(config *pkgconfig.Config, logger *logger.Logger, name string) *KafkaProducer {
	logger.Info("[%s] logger=kafka - enabled", name)
	k := &KafkaProducer{
		stopProcess:    make(chan bool),
		doneProcess:    make(chan bool),
		stopRun:        make(chan bool),
		doneRun:        make(chan bool),
		inputChan:      make(chan dnsutils.DNSMessage, config.Loggers.KafkaProducer.ChannelBufferSize),
		outputChan:     make(chan dnsutils.DNSMessage, config.Loggers.KafkaProducer.ChannelBufferSize),
		logger:         logger,
		config:         config,
		configChan:     make(chan *pkgconfig.Config),
		kafkaReady:     make(chan bool),
		kafkaReconnect: make(chan bool),
		name:           name,
	}

	k.ReadConfig()

	return k
}

func (k *KafkaProducer) GetName() string { return k.name }

func (c *KafkaProducer) AddDroppedRoute(wrk dnsutils.Worker) {}

func (k *KafkaProducer) AddDefaultRoute(wrk dnsutils.Worker) {}

func (k *KafkaProducer) SetLoggers(loggers []dnsutils.Worker) {}

func (k *KafkaProducer) ReadConfig() {
	if len(k.config.Loggers.RedisPub.TextFormat) > 0 {
		k.textFormat = strings.Fields(k.config.Loggers.RedisPub.TextFormat)
	} else {
		k.textFormat = strings.Fields(k.config.Global.TextFormat)
	}

	if k.config.Loggers.KafkaProducer.Compression != pkgconfig.CompressNone {
		switch k.config.Loggers.KafkaProducer.Compression {
		case pkgconfig.CompressGzip:
			k.compressCodec = &compress.GzipCodec
		case pkgconfig.CompressLz4:
			k.compressCodec = &compress.Lz4Codec
		case pkgconfig.CompressSnappy:
			k.compressCodec = &compress.SnappyCodec
		case pkgconfig.CompressZstd:
			k.compressCodec = &compress.ZstdCodec
		case pkgconfig.CompressNone:
			k.compressCodec = nil
		default:
			log.Fatal("kafka - invalid compress mode: ", k.config.Loggers.KafkaProducer.Compression)
		}
	}
}

func (k *KafkaProducer) ReloadConfig(config *pkgconfig.Config) {
	k.LogInfo("reload configuration!")
	k.configChan <- config
}

func (k *KafkaProducer) LogInfo(msg string, v ...interface{}) {
	k.logger.Info("["+k.name+"] logger=kafka - "+msg, v...)
}

func (k *KafkaProducer) LogError(msg string, v ...interface{}) {
	k.logger.Error("["+k.name+"] logger=kafka - "+msg, v...)
}

func (k *KafkaProducer) Channel() chan dnsutils.DNSMessage {
	return k.inputChan
}

func (k *KafkaProducer) Stop() {
	k.LogInfo("stopping to run...")
	k.stopRun <- true
	<-k.doneRun

	k.LogInfo("stopping to process...")
	k.stopProcess <- true
	<-k.doneProcess
}

func (k *KafkaProducer) Disconnect() {
	if k.kafkaConn != nil {
		k.LogInfo("closing  connection")
		k.kafkaConn.Close()
	}
}

func (k *KafkaProducer) ConnectToKafka(ctx context.Context, readyTimer *time.Timer) {
	for {
		readyTimer.Reset(time.Duration(10) * time.Second)

		if k.kafkaConn != nil {
			k.kafkaConn.Close()
			k.kafkaConn = nil
		}

		topic := k.config.Loggers.KafkaProducer.Topic
		partition := k.config.Loggers.KafkaProducer.Partition
		address := k.config.Loggers.KafkaProducer.RemoteAddress + ":" + strconv.Itoa(k.config.Loggers.KafkaProducer.RemotePort)

		k.LogInfo("connecting to kafka=%s partition=%d topic=%s", address, partition, topic)

		dialer := &kafka.Dialer{
			Timeout:   time.Duration(k.config.Loggers.KafkaProducer.ConnectTimeout) * time.Second,
			Deadline:  time.Now().Add(5 * time.Second),
			DualStack: true,
		}

		// enable TLS
		if k.config.Loggers.KafkaProducer.TLSSupport {
			tlsOptions := pkgconfig.TLSOptions{
				InsecureSkipVerify: k.config.Loggers.KafkaProducer.TLSInsecure,
				MinVersion:         k.config.Loggers.KafkaProducer.TLSMinVersion,
				CAFile:             k.config.Loggers.KafkaProducer.CAFile,
				CertFile:           k.config.Loggers.KafkaProducer.CertFile,
				KeyFile:            k.config.Loggers.KafkaProducer.KeyFile,
			}

			tlsConfig, err := pkgconfig.TLSClientConfig(tlsOptions)
			if err != nil {
				k.logger.Fatal("logger=kafka - tls config failed:", err)
			}
			dialer.TLS = tlsConfig
		}

		// SASL Support
		if k.config.Loggers.KafkaProducer.SaslSupport {
			switch k.config.Loggers.KafkaProducer.SaslMechanism {
			case pkgconfig.SASLMechanismPlain:
				mechanism := plain.Mechanism{
					Username: k.config.Loggers.KafkaProducer.SaslUsername,
					Password: k.config.Loggers.KafkaProducer.SaslPassword,
				}
				dialer.SASLMechanism = mechanism
			case pkgconfig.SASLMechanismScram:
				mechanism, err := scram.Mechanism(
					scram.SHA512,
					k.config.Loggers.KafkaProducer.SaslUsername,
					k.config.Loggers.KafkaProducer.SaslPassword,
				)
				if err != nil {
					panic(err)
				}
				dialer.SASLMechanism = mechanism
			}

		}

		// connect
		conn, err := dialer.DialLeader(ctx, "tcp", address, topic, partition)
		if err != nil {
			k.LogError("%s", err)
			k.LogInfo("retry to connect in %d seconds", k.config.Loggers.KafkaProducer.RetryInterval)
			time.Sleep(time.Duration(k.config.Loggers.KafkaProducer.RetryInterval) * time.Second)
			continue
		}

		k.kafkaConn = conn

		// block until is ready
		k.kafkaReady <- true
		k.kafkaReconnect <- true
	}
}

func (k *KafkaProducer) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	msgs := []kafka.Message{}
	buffer := new(bytes.Buffer)
	strDm := ""

	for _, dm := range *buf {
		switch k.config.Loggers.KafkaProducer.Mode {
		case pkgconfig.ModeText:
			strDm = dm.String(k.textFormat, k.config.Global.TextFormatDelimiter, k.config.Global.TextFormatBoundary)
		case pkgconfig.ModeJSON:
			json.NewEncoder(buffer).Encode(dm)
			strDm = buffer.String()
			buffer.Reset()
		case pkgconfig.ModeFlatJSON:
			flat, err := dm.Flatten()
			if err != nil {
				k.LogError("flattening DNS message failed: %e", err)
			}
			json.NewEncoder(buffer).Encode(flat)
			strDm = buffer.String()
			buffer.Reset()
		}

		msg := kafka.Message{
			Key:   []byte(dm.DNSTap.Identity),
			Value: []byte(strDm),
		}
		msgs = append(msgs, msg)

	}

	// add support for msg compression
	var err error
	if k.config.Loggers.KafkaProducer.Compression == pkgconfig.CompressNone {
		_, err = k.kafkaConn.WriteMessages(msgs...)
	} else {
		_, err = k.kafkaConn.WriteCompressedMessages(k.compressCodec, msgs...)
	}

	if err != nil {
		k.LogError("unable to write message", err.Error())
		k.kafkaConnected = false
		<-k.kafkaReconnect
	}

	// reset buffer
	*buf = nil
}

func (k *KafkaProducer) Run() {
	k.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, k.outputChan)
	subprocessors := transformers.NewTransforms(&k.config.OutgoingTransformers, k.logger, k.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go k.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-k.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			k.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-k.configChan:
			if !opened {
				return
			}
			k.config = cfg
			k.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-k.inputChan:
			if !opened {
				k.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// send to output channel
			k.outputChan <- dm
		}
	}
	k.LogInfo("run terminated")
}

func (k *KafkaProducer) Process() {
	ctx, cancelKafka := context.WithCancel(context.Background())
	defer cancelKafka() // Libérez les ressources liées au contexte

	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	readyTimer := time.NewTimer(time.Duration(10) * time.Second)

	// init flust timer for buffer
	flushInterval := time.Duration(k.config.Loggers.KafkaProducer.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	go k.ConnectToKafka(ctx, readyTimer)

	k.LogInfo("ready to process")

PROCESS_LOOP:
	for {
		select {
		case <-k.stopProcess:
			// closing kafka connection if exist
			k.Disconnect()
			k.doneProcess <- true
			break PROCESS_LOOP

		case <-readyTimer.C:
			k.LogError("failed to established connection")
			cancelKafka()

		case <-k.kafkaReady:
			k.LogInfo("connected with success")
			readyTimer.Stop()
			k.kafkaConnected = true

		// incoming dns message to process
		case dm, opened := <-k.outputChan:
			if !opened {
				k.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !k.kafkaConnected {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= k.config.Loggers.KafkaProducer.BufferSize {
				k.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !k.kafkaConnected {
				k.LogInfo("buffer cleared!")
				bufferDm = nil
				continue
			}

			if len(bufferDm) > 0 {
				k.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
	k.LogInfo("processing terminated")
}
