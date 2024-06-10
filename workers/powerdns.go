package workers

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

type PdnsServer struct {
	*GenericWorker
	connCounter uint64
}

func NewPdnsServer(next []Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *PdnsServer {
	w := &PdnsServer{GenericWorker: NewGenericWorker(config, logger, name, "powerdns", pkgconfig.DefaultBufferSize, pkgconfig.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.CheckConfig()
	return w
}

func (w *PdnsServer) CheckConfig() {
	if !netutils.IsValidTLS(w.GetConfig().Collectors.PowerDNS.TLSMinVersion) {
		w.LogFatal(pkgconfig.PrefixLogWorker + "[" + w.GetName() + "] invalid tls min version")
	}
}

func (w *PdnsServer) HandleConn(conn net.Conn, connID uint64, forceClose chan bool, wg *sync.WaitGroup) {
	// close connection on function exit
	defer func() {
		w.LogInfo("conn #%d - connection handler terminated", connID)
		netutils.Close(conn, w.GetConfig().Collectors.Dnstap.ResetConn)
		wg.Done()
	}()

	// get peer address
	peer := conn.RemoteAddr().String()
	peerName := netutils.GetPeerName(peer)
	w.LogInfo("new connection #%d from %s (%s)", connID, peer, peerName)

	// start protobuf subprocessor
	pdnsProcessor := NewPdnsProcessor(int(connID), peerName, w.GetConfig(), w.GetLogger(), w.GetName(), w.GetConfig().Collectors.PowerDNS.ChannelBufferSize)
	pdnsProcessor.SetDefaultRoutes(w.GetDefaultRoutes())
	pdnsProcessor.SetDefaultDropped(w.GetDroppedRoutes())
	go pdnsProcessor.StartCollect()

	r := bufio.NewReader(conn)
	pbs := powerdns_protobuf.NewProtobufStream(r, conn, 5*time.Second)

	var err error
	var payload *powerdns_protobuf.ProtoPayload
	cleanup := make(chan struct{})

	// goroutine to close the connection properly
	go func() {
		defer func() {
			pdnsProcessor.Stop()
			w.LogInfo("conn #%d - cleanup connection handler terminated", connID)
		}()

		for {
			select {
			case <-forceClose:
				w.LogInfo("conn #%d - force to cleanup the connection handler", connID)
				netutils.Close(conn, w.GetConfig().Collectors.Dnstap.ResetConn)
				return
			case <-cleanup:
				w.LogInfo("conn #%d - cleanup the connection handler", connID)
				return
			}
		}
	}()

	for {
		payload, err = pbs.RecvPayload(false)
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
				w.LogError("conn #%d - powerdns reader error: %s", connID, err)
			}

			// exit goroutine
			close(cleanup)
			break
		}

		// send payload to the channel
		select {
		case pdnsProcessor.GetDataChannel() <- payload.Data(): // Successful send
		default:
			w.WorkerIsBusy("dnstap-processor")
		}
	}
}

func (w *PdnsServer) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	var connWG sync.WaitGroup
	connCleanup := make(chan bool)
	cfg := w.GetConfig().Collectors.PowerDNS

	// start to listen
	listener, err := netutils.StartToListen(
		cfg.ListenIP, cfg.ListenPort, "",
		cfg.TLSSupport, netutils.TLSVersion[cfg.TLSMinVersion],
		cfg.CertFile, cfg.KeyFile)
	if err != nil {
		w.LogFatal(pkgconfig.PrefixLogWorker+"["+w.GetName()+"] listening failed: ", err)
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

		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			if w.GetConfig().Collectors.Dnstap.RcvBufSize > 0 {
				before, actual, err := netutils.SetSockRCVBUF(conn, cfg.RcvBufSize, cfg.TLSSupport)
				if err != nil {
					w.LogFatal(pkgconfig.PrefixLogWorker+"["+w.GetName()+"] unable to set SO_RCVBUF: ", err)
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

var (
	ProtobufPowerDNSToDNSTap = map[string]string{
		"DNSQueryType":            "CLIENT_QUERY",
		"DNSResponseType":         "CLIENT_RESPONSE",
		"DNSOutgoingQueryType":    "RESOLVER_QUERY",
		"DNSIncomingResponseType": "RESOLVER_RESPONSE",
	}
)

type PdnsProcessor struct {
	*GenericWorker
	ConnID      int
	PeerName    string
	dataChannel chan []byte
}

func NewPdnsProcessor(connID int, peerName string, config *pkgconfig.Config, logger *logger.Logger, name string, size int) PdnsProcessor {
	w := PdnsProcessor{GenericWorker: NewGenericWorker(config, logger, name, "powerdns processor #"+strconv.Itoa(connID), size, pkgconfig.DefaultMonitor)}
	w.ConnID = connID
	w.PeerName = peerName
	w.dataChannel = make(chan []byte, size)
	return w
}

func (w *PdnsProcessor) GetDataChannel() chan []byte {
	return w.dataChannel
}

func (w *PdnsProcessor) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	pbdm := &powerdns_protobuf.PBDNSMessage{}

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare enabled transformers
	transforms := transformers.NewTransforms(&w.GetConfig().IngoingTransformers, w.GetLogger(), w.GetName(), defaultRoutes, w.ConnID)

	// read incoming dns message
	for {
		select {
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			transforms.ReloadConfig(&cfg.IngoingTransformers)

		case <-w.OnStop():
			transforms.Reset()
			close(w.GetDataChannel())
			return

		case data, opened := <-w.GetDataChannel():
			if !opened {
				w.LogInfo("channel closed, exit")
				return
			}
			// count global messages
			w.CountIngressTraffic()

			err := proto.Unmarshal(data, pbdm)
			if err != nil {
				w.LogError("pbdm decoding, %s", err)
				continue
			}

			// init dns message
			dm := dnsutils.DNSMessage{}
			dm.Init()

			// init powerdns with default values
			dm.PowerDNS = &dnsutils.PowerDNS{
				Tags:                  []string{},
				OriginalRequestSubnet: "",
				AppliedPolicy:         "",
				Metadata:              map[string]string{},
			}

			dm.DNSTap.Identity = string(pbdm.GetServerIdentity())
			dm.DNSTap.Operation = ProtobufPowerDNSToDNSTap[pbdm.GetType().String()]

			if ipVersion, valid := netutils.IPVersion[pbdm.GetSocketFamily().String()]; valid {
				dm.NetworkInfo.Family = ipVersion
			} else {
				dm.NetworkInfo.Family = pkgconfig.StrUnknown
			}
			dm.NetworkInfo.Protocol = pbdm.GetSocketProtocol().String()

			if pbdm.From != nil {
				dm.NetworkInfo.QueryIP = net.IP(pbdm.From).String()
			}
			dm.NetworkInfo.QueryPort = strconv.FormatUint(uint64(pbdm.GetFromPort()), 10)
			dm.NetworkInfo.ResponseIP = net.IP(pbdm.To).String()
			dm.NetworkInfo.ResponsePort = strconv.FormatUint(uint64(pbdm.GetToPort()), 10)

			dm.DNS.ID = int(pbdm.GetId())
			dm.DNS.Length = int(pbdm.GetInBytes())
			dm.DNSTap.TimeSec = int(pbdm.GetTimeSec())
			dm.DNSTap.TimeNsec = int(pbdm.GetTimeUsec()) * 1e3

			if int(pbdm.Type.Number())%2 == 1 {
				dm.DNS.Type = dnsutils.DNSQuery
			} else {
				dm.DNS.Type = dnsutils.DNSReply

				tsQuery := float64(pbdm.Response.GetQueryTimeSec()) + float64(pbdm.Response.GetQueryTimeUsec())/1e6
				tsReply := float64(pbdm.GetTimeSec()) + float64(pbdm.GetTimeUsec())/1e6

				// convert latency to human
				dm.DNSTap.Latency = tsReply - tsQuery
				dm.DNSTap.LatencySec = fmt.Sprintf("%.6f", dm.DNSTap.Latency)
				dm.DNS.Rcode = dnsutils.RcodeToString(int(pbdm.Response.GetRcode()))
			}

			// compute timestamp
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			dm.DNSTap.Timestamp = ts.UnixNano()
			dm.DNSTap.TimestampRFC3339 = ts.UTC().Format(time.RFC3339Nano)

			dm.DNS.Qname = pbdm.Question.GetQName()
			// remove ending dot ?
			dm.DNS.Qname = strings.TrimSuffix(dm.DNS.Qname, ".")

			// get query type
			dm.DNS.Qtype = dnsutils.RdatatypeToString(int(pbdm.Question.GetQType()))

			// get specific powerdns params
			pdns := dnsutils.PowerDNS{}

			// get PowerDNS OriginalRequestSubnet
			ip := pbdm.GetOriginalRequestorSubnet()
			if len(ip) == 4 {
				addr := make(net.IP, net.IPv4len)
				copy(addr, ip)
				pdns.OriginalRequestSubnet = addr.String()
			}
			if len(ip) == 16 {
				addr := make(net.IP, net.IPv6len)
				copy(addr, ip)
				pdns.OriginalRequestSubnet = addr.String()
			}

			// get PowerDNS tags
			tags := pbdm.GetResponse().GetTags()
			if tags == nil {
				tags = []string{}
			}
			pdns.Tags = tags

			// get PowerDNS policy applied
			pdns.AppliedPolicy = pbdm.GetResponse().GetAppliedPolicy()
			pdns.AppliedPolicyHit = pbdm.GetResponse().GetAppliedPolicyHit()
			pdns.AppliedPolicyKind = pbdm.GetResponse().GetAppliedPolicyKind().String()
			pdns.AppliedPolicyTrigger = pbdm.GetResponse().GetAppliedPolicyTrigger()
			pdns.AppliedPolicyType = pbdm.GetResponse().GetAppliedPolicyType().String()

			// get PowerDNS metadata
			metas := make(map[string]string)
			for _, e := range pbdm.GetMeta() {
				metas[e.GetKey()] = strings.Join(e.Value.StringVal, " ")
			}
			pdns.Metadata = metas

			// get http protocol version
			if pbdm.GetSocketProtocol().String() == "DOH" {
				pdns.HTTPVersion = pbdm.GetHttpVersion().String()
			}

			// finally set pdns to dns message
			dm.PowerDNS = &pdns

			// decode answers
			answers := []dnsutils.DNSAnswer{}
			RRs := pbdm.GetResponse().GetRrs()
			for j := range RRs {
				rdata := string(RRs[j].GetRdata())
				if RRs[j].GetType() == 1 {
					addr := make(net.IP, net.IPv4len)
					copy(addr, rdata[:net.IPv4len])
					rdata = addr.String()
				}
				if RRs[j].GetType() == 28 {
					addr := make(net.IP, net.IPv6len)
					copy(addr, rdata[:net.IPv6len])
					rdata = addr.String()
				}

				rr := dnsutils.DNSAnswer{
					Name:      RRs[j].GetName(),
					Rdatatype: dnsutils.RdatatypeToString(int(RRs[j].GetType())),
					Class:     dnsutils.ClassToString(int(RRs[j].GetClass())),
					TTL:       int(RRs[j].GetTtl()),
					Rdata:     rdata,
				}
				answers = append(answers, rr)
			}
			dm.DNS.DNSRRs.Answers = answers

			if w.GetConfig().Collectors.PowerDNS.AddDNSPayload {

				qname := dns.Fqdn(pbdm.Question.GetQName())
				newDNS := new(dns.Msg)
				newDNS.Id = uint16(pbdm.GetId())
				newDNS.Response = false

				question := dns.Question{
					Name:   qname,
					Qtype:  uint16(pbdm.Question.GetQType()),
					Qclass: uint16(pbdm.Question.GetQClass()),
				}
				newDNS.Question = append(newDNS.Question, question)

				if int(pbdm.Type.Number())%2 != 1 {
					newDNS.Response = true
					newDNS.Rcode = int(pbdm.Response.GetRcode())

					newDNS.Answer = []dns.RR{}
					rrs := pbdm.GetResponse().GetRrs()
					for j := range rrs {
						rrname := dns.Fqdn(rrs[j].GetName())
						switch rrs[j].GetType() {
						// A
						case 1:
							rdata := &dns.A{
								Hdr: dns.RR_Header{Name: rrname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								A:   net.IP(rrs[j].GetRdata()),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						// AAAA
						case 28:
							rdata := &dns.AAAA{
								Hdr:  dns.RR_Header{Name: rrname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								AAAA: net.IP(rrs[j].GetRdata()),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						// CNAME
						case 5:
							rdata := &dns.CNAME{
								Hdr:    dns.RR_Header{Name: rrname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								Target: dns.Fqdn(string(rrs[j].GetRdata())),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						}

					}

				}

				pktWire, err := newDNS.Pack()
				if err == nil {
					dm.DNS.Payload = pktWire
					if dm.DNS.Length == 0 {
						dm.DNS.Length = len(pktWire)
					}
				} else {
					dm.DNS.MalformedPacket = true
				}
			}

			// apply all enabled transformers
			transformResult, err := transforms.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// dispatch dns messages to connected loggers
			w.SendTo(defaultRoutes, defaultNames, dm)
		}
	}
}
