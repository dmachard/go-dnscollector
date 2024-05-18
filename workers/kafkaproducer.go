package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

type KafkaProducer struct {
	*GenericWorker
	textFormat                 []string
	kafkaConn                  *kafka.Conn
	kafkaReady, kafkaReconnect chan bool
	kafkaConnected             bool
	compressCodec              compress.Codec
}

func NewKafkaProducer(config *pkgconfig.Config, logger *logger.Logger, name string) *KafkaProducer {
	w := &KafkaProducer{GenericWorker: NewGenericWorker(config, logger, name, "kafka", config.Loggers.KafkaProducer.ChannelBufferSize, pkgconfig.DefaultMonitor)}
	w.kafkaReady = make(chan bool)
	w.kafkaReconnect = make(chan bool)
	w.ReadConfig()
	return w
}

func (w *KafkaProducer) ReadConfig() {
	if len(w.GetConfig().Loggers.KafkaProducer.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.KafkaProducer.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	if w.GetConfig().Loggers.KafkaProducer.Compression != pkgconfig.CompressNone {
		switch w.GetConfig().Loggers.KafkaProducer.Compression {
		case pkgconfig.CompressGzip:
			w.compressCodec = &compress.GzipCodec
		case pkgconfig.CompressLz4:
			w.compressCodec = &compress.Lz4Codec
		case pkgconfig.CompressSnappy:
			w.compressCodec = &compress.SnappyCodec
		case pkgconfig.CompressZstd:
			w.compressCodec = &compress.ZstdCodec
		case pkgconfig.CompressNone:
			w.compressCodec = nil
		default:
			w.LogFatal(pkgconfig.PrefixLogWorker+"["+w.GetName()+"] kafka - invalid compress mode: ", w.GetConfig().Loggers.KafkaProducer.Compression)
		}
	}
}

func (w *KafkaProducer) Disconnect() {
	if w.kafkaConn != nil {
		w.LogInfo("closing  connection")
		w.kafkaConn.Close()
	}
}

func (w *KafkaProducer) ConnectToKafka(ctx context.Context, readyTimer *time.Timer) {
	for {
		readyTimer.Reset(time.Duration(10) * time.Second)

		if w.kafkaConn != nil {
			w.kafkaConn.Close()
			w.kafkaConn = nil
		}

		topic := w.GetConfig().Loggers.KafkaProducer.Topic
		partition := w.GetConfig().Loggers.KafkaProducer.Partition
		address := w.GetConfig().Loggers.KafkaProducer.RemoteAddress + ":" + strconv.Itoa(w.GetConfig().Loggers.KafkaProducer.RemotePort)

		w.LogInfo("connecting to kafka=%s partition=%d topic=%s", address, partition, topic)

		dialer := &kafka.Dialer{
			Timeout:   time.Duration(w.GetConfig().Loggers.KafkaProducer.ConnectTimeout) * time.Second,
			Deadline:  time.Now().Add(5 * time.Second),
			DualStack: true,
		}

		// enable TLS
		if w.GetConfig().Loggers.KafkaProducer.TLSSupport {
			tlsOptions := netutils.TLSOptions{
				InsecureSkipVerify: w.GetConfig().Loggers.KafkaProducer.TLSInsecure,
				MinVersion:         w.GetConfig().Loggers.KafkaProducer.TLSMinVersion,
				CAFile:             w.GetConfig().Loggers.KafkaProducer.CAFile,
				CertFile:           w.GetConfig().Loggers.KafkaProducer.CertFile,
				KeyFile:            w.GetConfig().Loggers.KafkaProducer.KeyFile,
			}

			tlsConfig, err := netutils.TLSClientConfig(tlsOptions)
			if err != nil {
				w.LogFatal("logger=kafka - tls config failed:", err)
			}
			dialer.TLS = tlsConfig
		}

		// SASL Support
		if w.GetConfig().Loggers.KafkaProducer.SaslSupport {
			switch w.GetConfig().Loggers.KafkaProducer.SaslMechanism {
			case pkgconfig.SASLMechanismPlain:
				mechanism := plain.Mechanism{
					Username: w.GetConfig().Loggers.KafkaProducer.SaslUsername,
					Password: w.GetConfig().Loggers.KafkaProducer.SaslPassword,
				}
				dialer.SASLMechanism = mechanism
			case pkgconfig.SASLMechanismScram:
				mechanism, err := scram.Mechanism(
					scram.SHA512,
					w.GetConfig().Loggers.KafkaProducer.SaslUsername,
					w.GetConfig().Loggers.KafkaProducer.SaslPassword,
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
			w.LogError("%s", err)
			w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.KafkaProducer.RetryInterval)
			time.Sleep(time.Duration(w.GetConfig().Loggers.KafkaProducer.RetryInterval) * time.Second)
			continue
		}

		w.kafkaConn = conn

		// block until is ready
		w.kafkaReady <- true
		w.kafkaReconnect <- true
	}
}

func (w *KafkaProducer) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	msgs := []kafka.Message{}
	buffer := new(bytes.Buffer)
	strDm := ""

	for _, dm := range *buf {
		switch w.GetConfig().Loggers.KafkaProducer.Mode {
		case pkgconfig.ModeText:
			strDm = dm.String(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
		case pkgconfig.ModeJSON:
			json.NewEncoder(buffer).Encode(dm)
			strDm = buffer.String()
			buffer.Reset()
		case pkgconfig.ModeFlatJSON:
			flat, err := dm.Flatten()
			if err != nil {
				w.LogError("flattening DNS message failed: %e", err)
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
	if w.GetConfig().Loggers.KafkaProducer.Compression == pkgconfig.CompressNone {
		_, err = w.kafkaConn.WriteMessages(msgs...)
	} else {
		_, err = w.kafkaConn.WriteCompressedMessages(w.compressCodec, msgs...)
	}

	if err != nil {
		w.LogError("unable to write message", err.Error())
		w.kafkaConnected = false
		<-w.kafkaReconnect
	}

	// reset buffer
	*buf = nil
}

func (w *KafkaProducer) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

			// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *KafkaProducer) StartLogging() {
	w.LogInfo("worker is starting logging")
	defer w.LoggingDone()

	ctx, cancelKafka := context.WithCancel(context.Background())
	defer cancelKafka() // Libérez les ressources liées au contexte

	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flust timer for buffer
	readyTimer := time.NewTimer(time.Duration(10) * time.Second)

	// init flust timer for buffer
	flushInterval := time.Duration(w.GetConfig().Loggers.KafkaProducer.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	go w.ConnectToKafka(ctx, readyTimer)

	for {
		select {
		case <-w.OnLoggerStopped():
			// closing kafka connection if exist
			w.Disconnect()
			return

		case <-readyTimer.C:
			w.LogError("failed to established connection")
			cancelKafka()

		case <-w.kafkaReady:
			w.LogInfo("connected with success")
			readyTimer.Stop()
			w.kafkaConnected = true

		// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !w.kafkaConnected {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= w.GetConfig().Loggers.KafkaProducer.BufferSize {
				w.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if !w.kafkaConnected {
				bufferDm = nil
			}

			if len(bufferDm) > 0 {
				w.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
}
