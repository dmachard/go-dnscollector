//go:build linux
// +build linux

// Written by Noel Kuntze <noel.kuntze {@@@@@} thermi.consulting>
// Updating by Denis Machard

package workers

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/tzsp"
)

type TZSPSniffer struct {
	*pkgutils.GenericWorker
	listen net.UDPConn
}

func NewTZSP(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *TZSPSniffer {
	s := &TZSPSniffer{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "tzsp", pkgutils.DefaultBufferSize, pkgutils.DefaultMonitor)}
	s.SetDefaultRoutes(next)
	return s
}

func (w *TZSPSniffer) Listen() error {
	w.LogInfo("starting UDP server...")

	ServerAddr, err := net.ResolveUDPAddr("udp",
		fmt.Sprintf("%s:%d", w.GetConfig().Collectors.Tzsp.ListenIP, w.GetConfig().Collectors.Tzsp.ListenPort),
	)

	if err != nil {
		return err
	}

	ServerConn, err := net.ListenUDP("udp", ServerAddr)
	if err != nil {
		return err
	}
	file, err := ServerConn.File()

	if err != nil {
		return err
	}

	err = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1)
	if err != nil {
		return err
	}

	// calling File.Fd() disables the SetDeadline methods
	err = syscall.SetNonblock(int(file.Fd()), true)
	if err != nil {
		return err
	}

	w.LogInfo("is listening on %s", ServerConn.LocalAddr())
	w.listen = *ServerConn
	return nil
}

func (w *TZSPSniffer) StartCollect() {
	w.LogInfo("worker is starting collection")
	defer w.CollectDone()

	// start server
	if err := w.Listen(); err != nil {
		w.LogFatal(pkgutils.PrefixLogWorker+"["+w.GetName()+"] listening failed: ", err)
	}

	// init dns processor
	dnsProcessor := NewDNSProcessor(w.GetConfig(), w.GetLogger(), w.GetName(), w.GetConfig().Collectors.Tzsp.ChannelBufferSize)
	dnsProcessor.SetDefaultRoutes(w.GetDefaultRoutes())
	dnsProcessor.SetDefaultDropped(w.GetDroppedRoutes())
	go dnsProcessor.StartCollect()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func(ctx context.Context) {
		defer func() {
			dnsProcessor.Stop()
			w.LogInfo("read data terminated")
			defer close(done)
		}()

		buf := make([]byte, 1024)
		oob := make([]byte, 1024)

		var netErr net.Error
		for {
			select {
			case <-ctx.Done():
				w.LogInfo("stopping UDP server...")
				w.listen.Close()
				return
			default:
				w.listen.SetReadDeadline(time.Now().Add(1 * time.Second))
				bufN, oobn, _, _, err := w.listen.ReadMsgUDPAddrPort(buf, oob)
				if err != nil {
					if errors.As(err, &netErr) && netErr.Timeout() {
						continue
					}
					w.LogFatal(pkgutils.PrefixLogWorker+"["+w.GetName()+"] read msg", err)
				}
				if bufN == 0 {
					w.LogFatal(pkgutils.PrefixLogWorker + "[" + w.GetName() + "] read msg, buffer is empty")
				}
				if bufN > len(buf) {
					w.LogFatal(pkgutils.PrefixLogWorker + "[" + w.GetName() + "] read msg, bufer overflow")
				}
				if oobn == 0 {
					w.LogFatal(pkgutils.PrefixLogWorker + "[" + w.GetName() + "] read msg, oob missing")
				}
				scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
				if err != nil {
					w.LogFatal(pkgutils.PrefixLogWorker+"["+w.GetName()+"] parse control msg", err)
				}
				if len(scms) != 1 {
					w.LogInfo("len(scms) != 1")
					continue
				}
				scm := scms[0]
				if scm.Header.Type != syscall.SCM_TIMESTAMPNS {
					w.LogFatal(pkgutils.PrefixLogWorker + "[" + w.GetName() + "] scm timestampns missing")
				}
				tsec := binary.LittleEndian.Uint32(scm.Data[:4])
				nsec := binary.LittleEndian.Uint32(scm.Data[8:12])

				// copy packet data from buffer
				pkt := make([]byte, bufN)
				copy(pkt, buf[:bufN])

				tzspPacket, err := tzsp.Parse(pkt)

				if err != nil {
					w.LogError("Failed to parse packet: ", err)
					continue
				}

				var eth layers.Ethernet
				var ip4 layers.IPv4
				var ip6 layers.IPv6
				var tcp layers.TCP
				var udp layers.UDP
				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
				decodedLayers := make([]gopacket.LayerType, 0, 4)

				// decode-it
				parser.DecodeLayers(tzspPacket.Data, &decodedLayers)

				dm := dnsutils.DNSMessage{}
				dm.Init()

				ignorePacket := false
				for _, layertyp := range decodedLayers {
					switch layertyp {
					case layers.LayerTypeIPv4:
						dm.NetworkInfo.Family = netutils.ProtoIPv4
						dm.NetworkInfo.QueryIP = ip4.SrcIP.String()
						dm.NetworkInfo.ResponseIP = ip4.DstIP.String()

					case layers.LayerTypeIPv6:
						dm.NetworkInfo.QueryIP = ip6.SrcIP.String()
						dm.NetworkInfo.ResponseIP = ip6.DstIP.String()
						dm.NetworkInfo.Family = netutils.ProtoIPv6

					case layers.LayerTypeUDP:
						dm.NetworkInfo.QueryPort = fmt.Sprint(int(udp.SrcPort))
						dm.NetworkInfo.ResponsePort = fmt.Sprint(int(udp.DstPort))
						dm.DNS.Payload = udp.Payload
						dm.DNS.Length = len(udp.Payload)
						dm.NetworkInfo.Protocol = netutils.ProtoUDP

					case layers.LayerTypeTCP:
						if len(tcp.Payload) < 12 {
							// packet way too short; 12 byte is the minimum size a DNS packet (header only,
							// no questions, answers, authorities, or additional RRs)
							continue
						}
						dnsLengthField := binary.BigEndian.Uint16(tcp.Payload[0:2])
						if len(tcp.Payload) < int(dnsLengthField) {
							ignorePacket = true
							continue
						}

						dm.NetworkInfo.QueryPort = fmt.Sprint(int(tcp.SrcPort))
						dm.NetworkInfo.ResponsePort = fmt.Sprint(int(tcp.DstPort))
						dm.DNS.Payload = tcp.Payload[2:]
						dm.DNS.Length = len(tcp.Payload[2:])
						dm.NetworkInfo.Protocol = netutils.ProtoTCP
					}
				}

				if !ignorePacket {
					dm.DNSTap.Identity = w.GetConfig().GetServerIdentity()

					// set timestamp
					dm.DNSTap.TimeSec = int(tsec)
					dm.DNSTap.TimeNsec = int(nsec)

					// just decode QR
					if len(dm.DNS.Payload) < 4 {
						continue
					}

					dnsProcessor.GetInputChannel() <- dm
				}
			}
		}
	}(ctx)

	// main loop
	for {
		select {
		case <-w.OnStop():
			w.LogInfo("stopping read goroutine")
			cancel()
			<-done
			return

		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
		}
	}
}
