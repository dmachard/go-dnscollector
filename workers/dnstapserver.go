package workers

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/transformers"
	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/segmentio/kafka-go/compress"
	"google.golang.org/protobuf/proto"
)

type DnstapServer struct {
	*GenericWorker
	connCounter uint64
}

func NewDnstapServer(next []Worker, cfg *config.Config, logger *logger.Logger, name string) *DnstapServer {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &DnstapServer{GenericWorker: NewGenericWorker(cfg, logger, name, "dnstap", bufSize, config.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.CheckConfig()
	return w
}

func (w *DnstapServer) CheckConfig() {
	if !netutils.IsValidTLS(w.GetConfig().Collectors.Dnstap.TLSMinVersion) {
		w.LogFatal(config.PrefixLogWorker + "[" + w.GetName() + "] dnstap - invalid tls min version")
	}
}

func (w *DnstapServer) HandleConn(conn net.Conn, connID uint64, forceClose chan bool, wg *sync.WaitGroup) {
	// get peer address
	peer := conn.RemoteAddr().String()
	peerName := netutils.GetPeerName(peer)
	w.LogInfo("conn #%d - new connection from %s (%s)", connID, peer, peerName)

	// start dnstap processor and run it
	bufSize := w.GetConfig().Global.Worker.ChannelBufferSize
	dnstapProcessor := NewDNSTapProcessor(int(connID), peerName, w.GetConfig(), w.GetLogger(), w.GetName(), bufSize)
	dnstapProcessor.SetMetrics(w.GetMetrics())
	dnstapProcessor.SetDefaultRoutes(w.GetDefaultRoutes())
	dnstapProcessor.SetDefaultDropped(w.GetDroppedRoutes())
	go dnstapProcessor.StartCollect()

	// close connection and stop processor on function exit
	defer func() {
		w.LogInfo("conn #%d - connection handler terminated", connID)
		netutils.Close(conn, w.GetConfig().Collectors.Dnstap.ResetConn)
		dnstapProcessor.Stop()
		wg.Done()
	}()

	readBufSize := w.GetConfig().Collectors.Dnstap.ReadBufferSize
	if readBufSize <= 0 {
		readBufSize = 4096
	}
	fsReader := bufio.NewReaderSize(conn, readBufSize)
	fsWriter := bufio.NewWriter(conn)
	handshakeTimeout := time.Duration(w.GetConfig().Global.Framestream.HandshakeTimeout) * time.Second
	contentType := []byte(w.GetConfig().Global.Framestream.ContentType)
	fs := framestream.NewFstrm(fsReader, fsWriter, conn, handshakeTimeout, contentType, true)
	fs.SetControlFrameMaxLength(w.GetConfig().Global.Framestream.ControlFrameMaxLength)
	fs.SetDataFrameMaxLength(w.GetConfig().Global.Framestream.DataFrameMaxLength)

	// framestream as receiver
	if err := fs.InitReceiver(); err != nil {
		w.LogError("conn #%d - stream initialization: %s", connID, err)
	} else {
		w.LogInfo("conn #%d - receiver framestream initialized (data-frame-max-length: %d, control-frame-max-length: %d)",
			connID,
			w.GetConfig().Global.Framestream.DataFrameMaxLength,
			w.GetConfig().Global.Framestream.ControlFrameMaxLength,
		)
	}

	// process incoming frame and send it to dnstap consumer channel
	var err error
	var frame *framestream.Frame
	cleanup := make(chan struct{})

	// goroutine to close the connection properly
	go func() {
		defer func() {
			w.LogInfo("conn #%d - cleanup connection handler terminated", connID)
		}()

		select {
		case <-forceClose:
			w.LogInfo("conn #%d - force to cleanup the connection handler", connID)
			netutils.Close(conn, w.GetConfig().Collectors.Dnstap.ResetConn)
		case <-cleanup:
			w.LogInfo("conn #%d - cleanup the connection handler", connID)
		}
	}()

	batchSize := w.GetBatchSize()
	useUpstreamBatching := w.GetConfig().Collectors.Dnstap.UpstreamBatching
	var curRawBatch *dnsutils.RawBatch
	if useUpstreamBatching {
		curRawBatch = dnsutils.AcquireRawBatch()
	}

	flushRawBatch := func() {
		if !useUpstreamBatching || curRawBatch == nil || len(curRawBatch.Frames) == 0 {
			return
		}
		select {
		case dnstapProcessor.GetBatchChannel() <- curRawBatch:
			curRawBatch = dnsutils.AcquireRawBatch()
		default:
			w.WorkerIsBusy("dnstap-processor", len(curRawBatch.Frames))
			curRawBatch.Release()
			curRawBatch = dnsutils.AcquireRawBatch()
		}
	}
	defer func() {
		flushRawBatch()
		if curRawBatch != nil {
			curRawBatch.Release()
		}
	}()

	// handle incoming frame
	for {
		if w.GetConfig().Collectors.Dnstap.Compression == config.CompressNone {
			frame, err = fs.RecvFrame(false)
		} else {
			frame, err = fs.RecvCompressedFrame(&compress.GzipCodec, false)
		}
		if err != nil {
			connClosed := false

			var opErr *net.OpError
			if errors.As(err, &opErr) {
				if errors.Is(opErr, net.ErrClosed) {
					connClosed = true
				}
			}
			if errors.Is(err, io.EOF) {
				connClosed = true
			}

			if connClosed {
				w.LogInfo("conn #%d - connection closed with peer %s", connID, peer)
			} else {
				w.LogError("conn #%d - framestream reader error: %s", connID, err)
			}
			flushRawBatch()
			// exit goroutine
			close(cleanup)
			break
		}

		if frame.IsControl() {
			if err := fs.ResetReceiver(frame); err != nil {
				if errors.Is(err, io.EOF) {
					w.LogInfo("conn #%d - framestream reset by sender", connID)
				} else {
					w.LogError("conn #%d - unexpected control framestream: %s", connID, err)
				}

			}

			flushRawBatch()
			// exit goroutine
			close(cleanup)
			break
		}

		if w.GetConfig().Collectors.Dnstap.Compression == config.CompressNone {
			if useUpstreamBatching {
				curRawBatch.Frames = append(curRawBatch.Frames, frame.Data())
				if len(curRawBatch.Frames) >= batchSize || fsReader.Buffered() == 0 {
					flushRawBatch()
				}
			} else {
				select {
				case dnstapProcessor.GetDataChannel() <- frame.Data():
				default:
					w.WorkerIsBusy("dnstap-processor", 1)
				}
			}
		} else {
			// ignore first 4 bytes
			data := frame.Data()[4:]
			validFrame := true
			for len(data) >= 4 {
				// get frame size
				payloadSize := binary.BigEndian.Uint32(data[:4])
				data = data[4:]

				// enough next data ?
				if uint32(len(data)) < payloadSize {
					validFrame = false
					break
				}
				if useUpstreamBatching {
					curRawBatch.Frames = append(curRawBatch.Frames, data[:payloadSize])
					if len(curRawBatch.Frames) >= batchSize {
						flushRawBatch()
					}
				} else {
					select {
					case dnstapProcessor.GetDataChannel() <- data[:payloadSize]:
					default:
						w.WorkerIsBusy("dnstap-processor", 1)
					}
				}

				// continue for next
				data = data[payloadSize:]
			}
			if useUpstreamBatching && fsReader.Buffered() == 0 {
				flushRawBatch()
			}
			if !validFrame {
				w.LogError("conn #%d - invalid compressed frame received", connID)
				continue
			}
		}
	}
}

func (w *DnstapServer) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	var connWG sync.WaitGroup
	connCleanup := make(chan bool)
	cfg := w.GetConfig().Collectors.Dnstap

	// start to listen
	listener, err := netutils.StartToListen(
		cfg.ListenIP, cfg.ListenPort, cfg.SockPath,
		cfg.TLSSupport, netutils.TLSVersion[cfg.TLSMinVersion],
		cfg.CertFile, cfg.KeyFile)
	if err != nil {
		w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] listen error: ", err)
	}
	w.LogInfo("listening on %s", listener.Addr())

	// goroutine to Accept() blocks waiting for new connection.
	acceptChan := make(chan net.Conn)
	netutils.AcceptConnections(listener, acceptChan)

	// main loop
	for {
		select {
		case <-w.OnStop():
			w.LogInfo("stop to listen...")
			listener.Close()

			w.LogInfo("closing connected peers...")
			close(connCleanup)
			connWG.Wait()
			return

		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.CheckConfig()

		// new incoming connection
		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			if len(cfg.SockPath) == 0 && cfg.RcvBufSize > 0 {
				before, actual, err := netutils.SetSockRCVBUF(conn, cfg.RcvBufSize, cfg.TLSSupport)
				if err != nil {
					w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] unable to set SO_RCVBUF: ", err)
				}
				w.LogInfo("set SO_RCVBUF option, value before: %d, desired: %d, actual: %d", before, cfg.RcvBufSize, actual)
			}

			// handle the connection
			connWG.Add(1)
			connID := atomic.AddUint64(&w.connCounter, 1)
			go w.HandleConn(conn, connID, connCleanup, &connWG)
		}

	}
}

func GetFakeDNSTap(dnsquery []byte) *dnstap.Dnstap {
	dtQuery := &dnstap.Dnstap{}

	dt := dnstap.Dnstap_MESSAGE
	dtQuery.Identity = []byte("dnstap-generator")
	dtQuery.Version = []byte("-")
	dtQuery.Type = &dt

	mt := dnstap.Message_CLIENT_QUERY
	sf := dnstap.SocketFamily_INET
	sp := dnstap.SocketProtocol_UDP

	now := time.Now()
	tsec := uint64(now.Unix())
	tnsec := uint32(uint64(now.UnixNano()) - uint64(now.Unix())*1e9)

	rport := uint32(53)
	qport := uint32(5300)

	msg := &dnstap.Message{Type: &mt}
	msg.SocketFamily = &sf
	msg.SocketProtocol = &sp
	msg.QueryAddress = net.ParseIP("127.0.0.1").To4()
	msg.QueryPort = &qport
	msg.ResponseAddress = net.ParseIP("127.0.0.2").To4()
	msg.ResponsePort = &rport

	msg.QueryMessage = dnsquery
	msg.QueryTimeSec = &tsec
	msg.QueryTimeNsec = &tnsec

	dtQuery.Message = msg
	return dtQuery
}

type DNSTapProcessor struct {
	*GenericWorker
	ConnID       int
	PeerName     string
	dataChannel  chan []byte
	batchChannel chan *dnsutils.RawBatch
}

func NewDNSTapProcessor(connID int, peerName string, cfg *config.Config, logger *logger.Logger, name string, size int) DNSTapProcessor {
	w := DNSTapProcessor{GenericWorker: NewGenericWorker(cfg, logger, name, "(conn #"+strconv.Itoa(connID)+") dnstap processor", size, config.DefaultMonitor)}
	w.ConnID = connID
	w.PeerName = peerName
	w.dataChannel = make(chan []byte, size)
	batchSize := w.GetBatchSize()
	batchChanSize := 100
	if batchSize > 0 {
		batchChanSize = size / batchSize
		if batchChanSize < 100 {
			batchChanSize = 100
		}
	}
	w.batchChannel = make(chan *dnsutils.RawBatch, batchChanSize)
	return w
}

func (w *DNSTapProcessor) GetDataChannel() chan []byte {
	return w.dataChannel
}

func (w *DNSTapProcessor) GetBatchChannel() chan *dnsutils.RawBatch {
	return w.batchChannel
}

func (w *DNSTapProcessor) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	numWorkers := w.GetConfig().Collectors.Dnstap.NumWorkers
	if numWorkers > 0 {
		var wg sync.WaitGroup
		workerCfgChans := make([]chan *config.Config, numWorkers)

		for i := 0; i < numWorkers; i++ {
			cfgChan := make(chan *config.Config, 10)
			workerCfgChans[i] = cfgChan
			wg.Add(1)

			go func(cChan chan *config.Config) {
				defer wg.Done()

				dt := &dnstap.Dnstap{}
				edt := &dnsutils.ExtendedDnstap{}
				fCache := &frameCache{}
				transforms := transformers.NewTransforms(&w.GetConfig().IngoingTransformers, w.GetLogger(), w.GetName(), defaultRoutes, w.ConnID)
				batchSize := w.GetBatchSize()
				curBatch := dnsutils.AcquireDNSMessageBatch(batchSize)
				for {
					select {
					case cfg := <-cChan:
						transforms.ReloadConfig(&cfg.IngoingTransformers)

					case batch, opened := <-w.GetBatchChannel():
						if !opened {
							if len(curBatch.Messages) > 0 {
								w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
							} else {
								curBatch.Release()
							}
							transforms.Reset()
							return
						}
						for _, data := range batch.Frames {
							dm, drop := w.processFrame(data, dt, edt, &transforms, fCache, droppedRoutes, droppedNames)
							if dm != nil && !drop {
								curBatch.Messages = append(curBatch.Messages, dm)
								if len(curBatch.Messages) >= batchSize {
									w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
									curBatch = dnsutils.AcquireDNSMessageBatch(batchSize)
								}
							}
						}
						batch.Release()
						if len(curBatch.Messages) > 0 && len(w.GetBatchChannel()) == 0 {
							w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
							curBatch = dnsutils.AcquireDNSMessageBatch(batchSize)
						}

					case data, opened := <-w.GetDataChannel():
						if !opened {
							if len(curBatch.Messages) > 0 {
								w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
							} else {
								curBatch.Release()
							}
							transforms.Reset()
							return
						}
						dm, drop := w.processFrame(data, dt, edt, &transforms, fCache, droppedRoutes, droppedNames)
						if dm != nil && !drop {
							curBatch.Messages = append(curBatch.Messages, dm)
							if len(curBatch.Messages) >= batchSize || len(w.GetDataChannel()) == 0 {
								w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
								curBatch = dnsutils.AcquireDNSMessageBatch(batchSize)
							}
						}
					}
				}
			}(cfgChan)
		}

		for {
			select {
			case cfg := <-w.NewConfig():
				w.SetConfig(cfg)
				for _, ch := range workerCfgChans {
					ch <- cfg
				}

			case <-w.OnStop():
				close(w.GetDataChannel())
				close(w.GetBatchChannel())
				wg.Wait()
				return
			}
		}
	} else {
		dt := &dnstap.Dnstap{}
		edt := &dnsutils.ExtendedDnstap{}
		fCache := &frameCache{}
		transforms := transformers.NewTransforms(&w.GetConfig().IngoingTransformers, w.GetLogger(), w.GetName(), defaultRoutes, w.ConnID)
		batchSize := w.GetBatchSize()
		curBatch := dnsutils.AcquireDNSMessageBatch(batchSize)

		// read incoming dns message
		for {
			select {
			case cfg := <-w.NewConfig():
				w.SetConfig(cfg)
				transforms.ReloadConfig(&cfg.IngoingTransformers)

			case <-w.OnStop():
				if len(curBatch.Messages) > 0 {
					w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
				} else {
					curBatch.Release()
				}
				transforms.Reset()
				close(w.GetDataChannel())
				close(w.GetBatchChannel())
				return

			case batch, opened := <-w.GetBatchChannel():
				if !opened {
					if len(curBatch.Messages) > 0 {
						w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
					} else {
						curBatch.Release()
					}
					w.LogInfo("batch channel closed, exit")
					return
				}
				for _, data := range batch.Frames {
					dm, drop := w.processFrame(data, dt, edt, &transforms, fCache, droppedRoutes, droppedNames)
					if dm != nil && !drop {
						curBatch.Messages = append(curBatch.Messages, dm)
						if len(curBatch.Messages) >= batchSize {
							w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
							curBatch = dnsutils.AcquireDNSMessageBatch(batchSize)
						}
					}
				}
				batch.Release()
				if len(curBatch.Messages) > 0 && len(w.GetBatchChannel()) == 0 {
					w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
					curBatch = dnsutils.AcquireDNSMessageBatch(batchSize)
				}

			case data, opened := <-w.GetDataChannel():
				if !opened {
					if len(curBatch.Messages) > 0 {
						w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
					} else {
						curBatch.Release()
					}
					w.LogInfo("channel closed, exit")
					return
				}
				dm, drop := w.processFrame(data, dt, edt, &transforms, fCache, droppedRoutes, droppedNames)
				if dm != nil && !drop {
					curBatch.Messages = append(curBatch.Messages, dm)
					if len(curBatch.Messages) >= batchSize || len(w.GetDataChannel()) == 0 {
						w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
						curBatch = dnsutils.AcquireDNSMessageBatch(batchSize)
					}
				}
			}
		}
	}
}

type frameCache struct {
	lastIdBytes  []byte
	lastIdStr    string
	lastVerBytes []byte
	lastVerStr   string
}

func (w *DNSTapProcessor) processFrame(
	data []byte,
	dt *dnstap.Dnstap,
	edt *dnsutils.ExtendedDnstap,
	transforms *transformers.Transforms,
	fCache *frameCache,
	droppedRoutes []chan *dnsutils.DNSMessageBatch,
	droppedNames []string,
) (*dnsutils.DNSMessage, bool) {
	// count global messages
	w.CountIngressTraffic()

	// init dns message from pool
	dm := dnsutils.AcquireDNSMessage()
	dm.DNSTap.PeerName = w.PeerName

	useFastDecoder := w.GetConfig().Collectors.Dnstap.FastDecoder && !w.GetConfig().Collectors.Dnstap.ExtendedSupport

	if useFastDecoder {
		err := dnsutils.DecodeDNSTapWire(data, dm)
		if err != nil {
			// fallback to standard protobuf unmarshal on error
			useFastDecoder = false
		}
	}

	if !useFastDecoder {
		err := proto.Unmarshal(data, dt)
		if err != nil {
			return nil, false
		}
	}

	if useFastDecoder {
		// apply frame-cache on Identity and Version strings if available
		if len(dm.DNSTap.Identity) > 0 && fCache != nil {
			idBytes := []byte(dm.DNSTap.Identity)
			if bytes.Equal(idBytes, fCache.lastIdBytes) {
				dm.DNSTap.Identity = fCache.lastIdStr
			} else {
				fCache.lastIdBytes = append(fCache.lastIdBytes[:0], idBytes...)
				fCache.lastIdStr = dm.DNSTap.Identity
			}
		}
		if len(dm.DNSTap.Version) > 0 && fCache != nil {
			verBytes := []byte(dm.DNSTap.Version)
			if bytes.Equal(verBytes, fCache.lastVerBytes) {
				dm.DNSTap.Version = fCache.lastVerStr
			} else {
				fCache.lastVerBytes = append(fCache.lastVerBytes[:0], verBytes...)
				fCache.lastVerStr = dm.DNSTap.Version
			}
		}
	} else {
		// init dns message with additional parts
		identity := dt.GetIdentity()
		if len(identity) > 0 {
			if fCache != nil && bytes.Equal(identity, fCache.lastIdBytes) {
				dm.DNSTap.Identity = fCache.lastIdStr
			} else {
				str := string(identity)
				if fCache != nil {
					fCache.lastIdBytes = append(fCache.lastIdBytes[:0], identity...)
					fCache.lastIdStr = str
				}
				dm.DNSTap.Identity = str
			}
		}

		version := dt.GetVersion()
		if len(version) > 0 {
			if fCache != nil && bytes.Equal(version, fCache.lastVerBytes) {
				dm.DNSTap.Version = fCache.lastVerStr
			} else {
				str := string(version)
				if fCache != nil {
					fCache.lastVerBytes = append(fCache.lastVerBytes[:0], version...)
					fCache.lastVerStr = str
				}
				dm.DNSTap.Version = str
			}
		}

		msgType := dt.GetMessage().GetType()
		dm.DNSTap.Operation = dnsutils.DnstapOperationToString(int(msgType))

		// extended extra field ?
		if w.GetConfig().Collectors.Dnstap.ExtendedSupport {
			err := proto.Unmarshal(dt.GetExtra(), edt)
			if err != nil {
				return nil, false
			}

			// get original extra value
			originalExtra := string(edt.GetOriginalDnstapExtra())
			if len(originalExtra) > 0 {
				dm.DNSTap.Extra = originalExtra
			}

			// get atags
			atags := edt.GetAtags()
			if atags != nil {
				dm.ATags = &dnsutils.TransformATags{
					Tags: atags.GetTags(),
				}
			}

			// get public suffix
			norm := edt.GetNormalize()
			if norm != nil {
				dm.PublicSuffix = &dnsutils.TransformPublicSuffix{}
				if len(norm.GetTld()) > 0 {
					dm.PublicSuffix.QnamePublicSuffix = norm.GetTld()
				}
				if len(norm.GetEtldPlusOne()) > 0 {
					dm.PublicSuffix.QnameEffectiveTLDPlusOne = norm.GetEtldPlusOne()
				}
			}

			// filtering
			sampleRate := edt.GetFiltering()
			if sampleRate != nil {
				dm.Filtering = &dnsutils.TransformFiltering{}
				dm.Filtering.SampleRate = int(sampleRate.SampleRate)
			}
		} else {
			extra := string(dt.GetExtra())
			if len(extra) > 0 {
				dm.DNSTap.Extra = extra
			}
		}

		switch dt.GetMessage().GetSocketFamily() {
		case dnstap.SocketFamily_INET:
			dm.NetworkInfo.Family = netutils.ProtoIPv4
		case dnstap.SocketFamily_INET6:
			dm.NetworkInfo.Family = netutils.ProtoIPv6
		default:
			qAddr := dt.GetMessage().GetQueryAddress()
			rAddr := dt.GetMessage().GetResponseAddress()
			if len(qAddr) == 4 || len(rAddr) == 4 {
				dm.NetworkInfo.Family = netutils.ProtoIPv4
			} else if len(qAddr) == 16 || len(rAddr) == 16 {
				dm.NetworkInfo.Family = netutils.ProtoIPv6
			} else {
				dm.NetworkInfo.Family = config.StrUnknown
			}
		}

		switch dt.GetMessage().GetSocketProtocol() {
		case dnstap.SocketProtocol_UDP:
			dm.NetworkInfo.Protocol = "UDP"
		case dnstap.SocketProtocol_TCP:
			dm.NetworkInfo.Protocol = "TCP"
		case dnstap.SocketProtocol_DOT:
			dm.NetworkInfo.Protocol = "DOT"
		case dnstap.SocketProtocol_DOH:
			dm.NetworkInfo.Protocol = "DOH"
		case dnstap.SocketProtocol_DNSCryptUDP:
			dm.NetworkInfo.Protocol = "DNSCryptUDP"
		case dnstap.SocketProtocol_DNSCryptTCP:
			dm.NetworkInfo.Protocol = "DNSCryptTCP"
		case dnstap.SocketProtocol_DOQ:
			dm.NetworkInfo.Protocol = "DOQ"
		default:
			dm.NetworkInfo.Protocol = config.StrUnknown
		}

		// decode query address and port
		queryip := dt.GetMessage().GetQueryAddress()
		if len(queryip) > 0 {
			dm.NetworkInfo.SetQueryIPBytes(queryip)
		}
		queryport := dt.GetMessage().GetQueryPort()
		if queryport > 0 {
			dm.NetworkInfo.QueryPort = dnsutils.FastPortToString(queryport)
		}

		// decode response address and port
		responseip := dt.GetMessage().GetResponseAddress()
		if len(responseip) > 0 {
			dm.NetworkInfo.SetResponseIPBytes(responseip)
		}
		responseport := dt.GetMessage().GetResponsePort()
		if responseport > 0 {
			dm.NetworkInfo.ResponsePort = dnsutils.FastPortToString(responseport)
		}

		// get dns payload and timestamp according to the type (query or response)
		op := int(msgType)
		if op%2 == 1 {
			dnsPayload := dt.GetMessage().GetQueryMessage()
			dm.DNS.Payload = dnsPayload
			dm.DNS.Length = len(dnsPayload)
			dm.DNS.Type = dnsutils.DNSQuery
			dm.DNSTap.TimeSec = int(dt.GetMessage().GetQueryTimeSec())
			dm.DNSTap.TimeNsec = int(dt.GetMessage().GetQueryTimeNsec())
		} else {
			dnsPayload := dt.GetMessage().GetResponseMessage()
			dm.DNS.Payload = dnsPayload
			dm.DNS.Length = len(dnsPayload)
			dm.DNS.Type = dnsutils.DNSReply
			dm.DNSTap.TimeSec = int(dt.GetMessage().GetResponseTimeSec())
			dm.DNSTap.TimeNsec = int(dt.GetMessage().GetResponseTimeNsec())

			tsQuery := float64(dt.GetMessage().GetQueryTimeSec()) + float64(dt.GetMessage().GetQueryTimeNsec())/1e9
			tsReply := float64(dt.GetMessage().GetResponseTimeSec()) + float64(dt.GetMessage().GetResponseTimeNsec())/1e9

			// compute latency
			if tsQuery != 0 && tsReply >= tsQuery {
				dm.DNSTap.Latency = tsReply - tsQuery
				dm.DNSTap.LatencyMs = int((tsReply - tsQuery) * 1000)
			}
		}

		// policy
		policyType := dt.GetMessage().GetPolicy().GetType()
		if len(policyType) > 0 {
			dm.DNSTap.PolicyType = policyType
		}

		policyRule := string(dt.GetMessage().GetPolicy().GetRule())
		if len(policyRule) > 0 {
			dm.DNSTap.PolicyRule = policyRule
		}

		policyAction := dt.GetMessage().GetPolicy().GetAction().String()
		if len(policyAction) > 0 {
			dm.DNSTap.PolicyAction = policyAction
		}

		policyMatch := dt.GetMessage().GetPolicy().GetMatch().String()
		if len(policyMatch) > 0 {
			dm.DNSTap.PolicyMatch = policyMatch
		}

		policyValue := string(dt.GetMessage().GetPolicy().GetValue())
		if len(policyValue) > 0 {
			dm.DNSTap.PolicyValue = policyValue
		}

		// get http protocol
		httpProtocol := dt.GetMessage().GetHttpProtocol().String()
		if len(httpProtocol) > 0 {
			dm.DNSTap.HttpProtocol = httpProtocol
		}

		// decode query zone if provided
		queryZone := dt.GetMessage().GetQueryZone()
		if len(queryZone) > 0 {
			qz, _, err := dnsutils.ParseLabels(0, queryZone, true)
			if err != nil {
				w.LogError("invalid query zone: %v - %v", err, queryZone)
			}
			dm.DNSTap.QueryZone = qz
		}
	}

	// compute timestamp
	ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
	dm.DNSTap.Timestamp = ts.UnixNano()
	dm.DNSTap.TimestampRFC3339 = "-"

	// decode payload if provided
	if !w.GetConfig().Collectors.Dnstap.DisableDNSParser && len(dm.DNS.Payload) > 0 {
		dnsHeader, err := dnsutils.DecodeDNS(dm.DNS.Payload)
		if err != nil {
			dm.DNS.MalformedPacket = true
			if w.GetConfig().Global.Trace.LogMalformed {
				w.LogWarning("dns header parser stopped: %s", err)
				w.LogWarning("dump dns packet: %v", dm)
				w.LogWarning("dump dns payload: %v", dm.DNS.Payload)
			}
		}

		dm.DNS.QdCount = dnsHeader.Qdcount
		dm.DNS.AnCount = dnsHeader.Ancount
		dm.DNS.ArCount = dnsHeader.Arcount
		dm.DNS.NsCount = dnsHeader.Nscount

		if err = dnsutils.DecodePayload(dm, &dnsHeader, w.GetConfig()); err != nil {
			dm.DNS.MalformedPacket = true
			if w.GetConfig().Global.Trace.LogMalformed {
				w.LogWarning("dns payload parser stopped: %s", err)
				w.LogWarning("dump dns packet: %v", dm)
				w.LogWarning("dump dns payload: %v", dm.DNS.Payload)
			}
		}
	}

	// count output packets
	w.CountEgressTraffic()

	// apply all enabled transformers
	transformResult, err := transforms.ProcessMessage(dm)
	if err != nil {
		w.LogError(err.Error())
	}
	if transformResult == transformers.ReturnDrop {
		w.SendDroppedTo(droppedRoutes, droppedNames, dm)
		return nil, true
	}

	return dm, false
}

func init() {
	RegisterCollector("dnstap", func(c *config.Config) bool { return c.Collectors.Dnstap.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewDnstapServer(nil, c, l, s)
	})
}
