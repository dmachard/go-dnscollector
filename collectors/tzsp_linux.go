//go:build linux
// +build linux

// Written by Noel Kuntze <noel.kuntze {@@@@@} thermi.consulting>
// Updating by Denis Machard

package collectors

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
	"github.com/dmachard/go-dnscollector/processors"
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
	s := &TZSPSniffer{GenericWorker: pkgutils.NewGenericWorker(config, logger, name, "tzsp", pkgutils.DefaultBufferSize)}
	s.SetDefaultRoutes(next)
	return s
}

func (c *TZSPSniffer) Listen() error {
	c.LogInfo("starting UDP server...")

	ServerAddr, err := net.ResolveUDPAddr("udp",
		fmt.Sprintf("%s:%d", c.GetConfig().Collectors.Tzsp.ListenIP, c.GetConfig().Collectors.Tzsp.ListenPort),
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

	c.LogInfo("is listening on %s", ServerConn.LocalAddr())
	c.listen = *ServerConn
	return nil
}

func (c *TZSPSniffer) Run() {
	c.LogInfo("running collector...")
	defer func() {
		c.LogInfo("run terminated")
		c.StopIsDone()
	}()

	// start server
	if err := c.Listen(); err != nil {
		c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] listening failed: ", err)
	}

	// init dns processor
	dnsProcessor := processors.NewDNSProcessor(c.GetConfig(), c.GetLogger(), c.GetName(), c.GetConfig().Collectors.Tzsp.ChannelBufferSize)
	go dnsProcessor.Run(c.GetDefaultRoutes(), c.GetDroppedRoutes())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func(ctx context.Context) {
		defer func() {
			dnsProcessor.Stop()
			c.LogInfo("read data terminated")
			defer close(done)
		}()

		buf := make([]byte, 1024)
		oob := make([]byte, 1024)

		var netErr net.Error
		for {
			select {
			case <-ctx.Done():
				c.LogInfo("stopping UDP server...")
				c.listen.Close()
				return
			default:
				c.listen.SetReadDeadline(time.Now().Add(1 * time.Second))
				bufN, oobn, _, _, err := c.listen.ReadMsgUDPAddrPort(buf, oob)
				if err != nil {
					if errors.As(err, &netErr) && netErr.Timeout() {
						continue
					}
					c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] read msg", err)
				}
				if bufN == 0 {
					c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] read msg, buffer is empty")
				}
				if bufN > len(buf) {
					c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] read msg, bufer overflow")
				}
				if oobn == 0 {
					c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] read msg, oob missing")
				}
				scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
				if err != nil {
					c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] parse control msg", err)
				}
				if len(scms) != 1 {
					c.LogInfo("len(scms) != 1")
					continue
				}
				scm := scms[0]
				if scm.Header.Type != syscall.SCM_TIMESTAMPNS {
					c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] scm timestampns missing")
				}
				tsec := binary.LittleEndian.Uint32(scm.Data[:4])
				nsec := binary.LittleEndian.Uint32(scm.Data[8:12])

				// copy packet data from buffer
				pkt := make([]byte, bufN)
				copy(pkt, buf[:bufN])

				tzspPacket, err := tzsp.Parse(pkt)

				if err != nil {
					c.LogError("Failed to parse packet: ", err)
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
					dm.DNSTap.Identity = c.GetConfig().GetServerIdentity()

					// set timestamp
					dm.DNSTap.TimeSec = int(tsec)
					dm.DNSTap.TimeNsec = int(nsec)

					// just decode QR
					if len(dm.DNS.Payload) < 4 {
						continue
					}

					dnsProcessor.GetChannel() <- dm
				}
			}
		}
	}(ctx)

	// main loop
	for {
		select {
		case <-c.OnStop():
			c.LogInfo("stopping read goroutine")
			cancel()
			<-done
			return

		// save the new config
		case cfg := <-c.NewConfig():
			c.SetConfig(cfg)
		}
	}
}
