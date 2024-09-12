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
	kafkaReady, kafkaReconnect chan bool
	kafkaConnected             bool
	compressCodec              compress.Codec
	kafkaConns                 map[int]*kafka.Conn // Map to store connections by partition
	lastPartitionIndex         *int
}

func NewKafkaProducer(config *pkgconfig.Config, logger *logger.Logger, name string) *KafkaProducer {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Loggers.KafkaProducer.ChannelBufferSize > 0 {
		bufSize = config.Loggers.KafkaProducer.ChannelBufferSize
	}
	w := &KafkaProducer{
		GenericWorker:  NewGenericWorker(config, logger, name, "kafka", bufSize, pkgconfig.DefaultMonitor),
		kafkaReady:     make(chan bool),
		kafkaReconnect: make(chan bool),
		kafkaConns:     make(map[int]*kafka.Conn),
	}
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
	// Close all Kafka connections
	for _, conn := range w.kafkaConns {
		if conn != nil {
			w.LogInfo("closing connection per partition")
			conn.Close()
		}
	}
	w.kafkaConns = make(map[int]*kafka.Conn) // Clear the map
}

func (w *KafkaProducer) ConnectToKafka(ctx context.Context, readyTimer *time.Timer) {
	for {
		readyTimer.Reset(time.Duration(10) * time.Second)

		if len(w.kafkaConns) > 0 {
			w.Disconnect()
		}

		topic := w.GetConfig().Loggers.KafkaProducer.Topic
		partition := w.GetConfig().Loggers.KafkaProducer.Partition
		address := w.GetConfig().Loggers.KafkaProducer.RemoteAddress + ":" + strconv.Itoa(w.GetConfig().Loggers.KafkaProducer.RemotePort)

		if partition == nil {
			w.LogInfo("connecting to kafka=%s partition=all topic=%s", address, topic)
		} else {
			w.LogInfo("connecting to kafka=%s partition=%d topic=%s", address, *partition, topic)
		}

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

		var conn *kafka.Conn
		var err error

		if partition == nil {
			// Lookup partitions and create connections for each
			partitions, err := dialer.LookupPartitions(ctx, "tcp", address, topic)
			if err != nil {
				w.LogError("failed to lookup partitions:", err)
				w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.KafkaProducer.RetryInterval)
				time.Sleep(time.Duration(w.GetConfig().Loggers.KafkaProducer.RetryInterval) * time.Second)
				continue
			}
			for _, p := range partitions {
				conn, err = dialer.DialLeader(ctx, "tcp", address, p.Topic, p.ID)
				if err != nil {
					w.LogError("failed to dial leader for partition %d: %s", p.ID, err)
					w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.KafkaProducer.RetryInterval)
					time.Sleep(time.Duration(w.GetConfig().Loggers.KafkaProducer.RetryInterval) * time.Second)
					continue
				}
				w.kafkaConns[p.ID] = conn
			}
		} else {
			// DialLeader directly for a specific partition
			conn, err = dialer.DialLeader(ctx, "tcp", address, topic, *partition)
			if err != nil {
				w.LogError("failed to dial leader for partition %d and topic %s: %s", *partition, topic, err)
				w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.KafkaProducer.RetryInterval)
				time.Sleep(time.Duration(w.GetConfig().Loggers.KafkaProducer.RetryInterval) * time.Second)
				continue
			}
			w.kafkaConns[*partition] = conn
		}

		// block until is ready
		w.kafkaReady <- true
		w.kafkaReconnect <- true
	}
}

func (w *KafkaProducer) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	msgs := []kafka.Message{}
	buffer := new(bytes.Buffer)
	strDm := ""
	partition := w.GetConfig().Loggers.KafkaProducer.Partition

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

	// add support for msg compression and round robin
	var err error
	if partition == nil {
		if w.lastPartitionIndex == nil {
			w.lastPartitionIndex = new(int) // Initialiser l'index la première fois
		}
		numPartitions := len(w.kafkaConns)
		conn := w.kafkaConns[*w.lastPartitionIndex]
		if w.GetConfig().Loggers.KafkaProducer.Compression == pkgconfig.CompressNone {
			_, err = conn.WriteMessages(msgs...)
		} else {
			_, err = conn.WriteCompressedMessages(w.compressCodec, msgs...)
		}
		if err != nil {
			w.LogError("unable to write message", err.Error())
			w.kafkaConnected = false
			<-w.kafkaReconnect
		}

		// Move to the next partition in round-robin fashion
		*w.lastPartitionIndex = (*w.lastPartitionIndex + 1) % numPartitions
	} else {
		conn := w.kafkaConns[*partition]
		if w.GetConfig().Loggers.KafkaProducer.Compression == pkgconfig.CompressNone {
			_, err = conn.WriteMessages(msgs...)
		} else {
			_, err = conn.WriteCompressedMessages(w.compressCodec, msgs...)
		}
		if err != nil {
			w.LogError("unable to write message", err.Error())
			w.kafkaConnected = false
			<-w.kafkaReconnect
		}
	}

	// reset buffer
	*buf = nil
}

func (w *KafkaProducer) StartCollect() {
	w.LogInfo("starting data collection")
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
			// count global messages
			w.CountIngressTraffic()

			// apply tranforms, init dns message with additionnals parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.CountEgressTraffic()
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *KafkaProducer) StartLogging() {
	w.LogInfo("logging has started")
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
