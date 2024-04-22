//go:build linux
// +build linux

package collectors

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
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
)

type AfpacketSniffer struct {
	*pkgutils.Collector
	fd int
}

func NewAfpacketSniffer(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	s := &AfpacketSniffer{Collector: pkgutils.NewCollector(config, logger, name, "afpacket sniffer")}
	s.SetDefaultRoutes(next)
	return s
}

func (c *AfpacketSniffer) Listen() error {
	// raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, netutils.Htons(syscall.ETH_P_ALL))
	if err != nil {
		return err
	}

	// bind to device ?
	if c.GetConfig().Collectors.AfpacketLiveCapture.Device != "" {
		iface, err := net.InterfaceByName(c.GetConfig().Collectors.AfpacketLiveCapture.Device)
		if err != nil {
			return err
		}

		ll := syscall.SockaddrLinklayer{
			Ifindex: iface.Index,
		}

		if err := syscall.Bind(fd, &ll); err != nil {
			return err
		}

		c.LogInfo("binding with success to iface %q (index %d)", iface.Name, iface.Index)
	}

	// set nano timestamp
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1)
	if err != nil {
		return err
	}

	filter := netutils.GetBpfFilter(c.GetConfig().Collectors.AfpacketLiveCapture.Port)
	err = netutils.ApplyBpfFilter(filter, fd)
	if err != nil {
		return err
	}

	c.LogInfo("BPF filter applied")

	c.fd = fd
	return nil
}

func (c *AfpacketSniffer) Run() {
	c.LogInfo("running collector...")
	defer func() {
		c.LogInfo("run terminated")
		c.StopIsDone()
	}()

	if c.fd == 0 {
		if err := c.Listen(); err != nil {
			c.LogError("init raw socket failed: %v\n", err)
			os.Exit(1) // nolint
		}
	}

	dnsProcessor := processors.NewDNSProcessor(c.GetConfig(), c.GetLogger(), c.GetName(), c.GetConfig().Collectors.AfpacketLiveCapture.ChannelBufferSize)
	go dnsProcessor.Run(c.GetDefaultRoutes(), c.GetDroppedRoutes())

	dnsChan := make(chan netutils.DNSPacket)
	udpChan := make(chan gopacket.Packet)
	tcpChan := make(chan gopacket.Packet)
	fragIP4Chan := make(chan gopacket.Packet)
	fragIP6Chan := make(chan gopacket.Packet)

	netDecoder := &netutils.NetDecoder{}

	// defrag ipv4
	go netutils.IPDefragger(fragIP4Chan, udpChan, tcpChan)
	// defrag ipv6
	go netutils.IPDefragger(fragIP6Chan, udpChan, tcpChan)
	// tcp assembly
	go netutils.TCPAssembler(tcpChan, dnsChan, 0)
	// udp processor
	go netutils.UDPProcessor(udpChan, dnsChan, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func(ctx context.Context) {
		defer func() {
			dnsProcessor.Stop()
			netutils.RemoveBpfFilter(c.fd)
			syscall.Close(c.fd)
			c.LogInfo("read data terminated")
			defer close(done)
		}()

		buf := make([]byte, 65536)
		oob := make([]byte, 100)

		for {
			select {
			case <-ctx.Done():
				c.LogInfo("stopping sniffer...")
				syscall.Close(c.fd)
				return
			default:
				var fdSet syscall.FdSet
				fdSet.Bits[c.fd/64] |= 1 << (uint(c.fd) % 64)

				nReady, err := syscall.Select(c.fd+1, &fdSet, nil, nil, &syscall.Timeval{Sec: 1, Usec: 0})
				if err != nil {
					if errors.Is(err, syscall.EINTR) {
						continue
					}
					panic(err)
				}
				if nReady == 0 {
					continue
				}

				bufN, oobn, _, _, err := syscall.Recvmsg(c.fd, buf, oob, syscall.MSG_DONTWAIT)
				if err != nil {
					if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
						continue
					} else {
						c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"read data", err)
					}
				}
				if bufN == 0 {
					c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] buf empty")
				}
				if bufN > len(buf) {
					c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] buf overflow")
				}
				if oobn == 0 {
					c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] oob missing")
				}

				scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
				if err != nil {
					c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] control msg", err)
				}
				if len(scms) != 1 {
					continue
				}
				scm := scms[0]
				if scm.Header.Type != syscall.SCM_TIMESTAMPNS {
					c.LogFatal(pkgutils.PrefixLogCollector + "[" + c.GetName() + "] scm timestampns missing")
				}
				tsec := binary.LittleEndian.Uint32(scm.Data[:4])
				nsec := binary.LittleEndian.Uint32(scm.Data[8:12])
				timestamp := time.Unix(int64(tsec), int64(nsec))

				// copy packet data from buffer
				pkt := make([]byte, bufN)
				copy(pkt, buf[:bufN])

				// decode minimal layers
				packet := gopacket.NewPacket(pkt, netDecoder, gopacket.NoCopy)
				packet.Metadata().CaptureLength = len(packet.Data())
				packet.Metadata().Length = len(packet.Data())
				packet.Metadata().Timestamp = timestamp

				// some security checks
				if packet.NetworkLayer() == nil {
					continue
				}
				if packet.TransportLayer() == nil {
					continue
				}

				// ipv4 fragmented packet ?
				if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
					ip4 := packet.NetworkLayer().(*layers.IPv4)
					if ip4.Flags&layers.IPv4MoreFragments == 1 || ip4.FragOffset > 0 {
						fragIP4Chan <- packet
						continue
					}
				}

				// ipv6 fragmented packet ?
				if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
					v6frag := packet.Layer(layers.LayerTypeIPv6Fragment)
					if v6frag != nil {
						fragIP6Chan <- packet
						continue
					}
				}

				// tcp or udp packets ?
				if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
					udpChan <- packet
				}

				if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
					tcpChan <- packet
				}
			}
		}

	}(ctx)

	// prepare dns message
	dm := dnsutils.DNSMessage{}

	for {
		select {
		case <-c.OnStop():
			c.LogInfo("stop to listen...")
			cancel()
			<-done
			return

		// new config provided?
		case cfg := <-c.NewConfig():
			c.SetConfig(cfg)

			// send the config to the dns processor
			dnsProcessor.ConfigChan <- cfg

		// dns message to read ?
		case dnsPacket := <-dnsChan:
			// reset
			dm.Init()

			dm.NetworkInfo.Family = dnsPacket.IPLayer.EndpointType().String()
			dm.NetworkInfo.QueryIP = dnsPacket.IPLayer.Src().String()
			dm.NetworkInfo.ResponseIP = dnsPacket.IPLayer.Dst().String()
			dm.NetworkInfo.QueryPort = dnsPacket.TransportLayer.Src().String()
			dm.NetworkInfo.ResponsePort = dnsPacket.TransportLayer.Dst().String()
			dm.NetworkInfo.Protocol = dnsPacket.TransportLayer.EndpointType().String()

			dm.DNS.Payload = dnsPacket.Payload
			dm.DNS.Length = len(dnsPacket.Payload)

			dm.DNSTap.Identity = c.GetConfig().GetServerIdentity()

			timestamp := dnsPacket.Timestamp.UnixNano()
			seconds := timestamp / int64(time.Second)
			dm.DNSTap.TimeSec = int(seconds)
			dm.DNSTap.TimeNsec = int(timestamp - seconds*int64(time.Second)*int64(time.Nanosecond))

			// send DNS message to DNS processor
			dnsProcessor.GetChannel() <- dm
		}
	}
}
