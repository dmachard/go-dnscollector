//go:build linux
// +build linux

package workers

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type AfpacketSniffer struct {
	*GenericWorker
	fd int
}

func NewAfpacketSniffer(next []Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Collectors.AfpacketLiveCapture.ChannelBufferSize > 0 {
		bufSize = config.Collectors.AfpacketLiveCapture.ChannelBufferSize
	}
	w := &AfpacketSniffer{GenericWorker: NewGenericWorker(config, logger, name, "afpacket sniffer", bufSize, pkgconfig.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	return w
}

func (w *AfpacketSniffer) Listen() error {
	// raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, netutils.Htons(syscall.ETH_P_ALL))
	if err != nil {
		return err
	}

	// bind to device ?
	if w.GetConfig().Collectors.AfpacketLiveCapture.Device != "" {
		iface, err := net.InterfaceByName(w.GetConfig().Collectors.AfpacketLiveCapture.Device)
		if err != nil {
			return err
		}

		ll := syscall.SockaddrLinklayer{
			Ifindex: iface.Index,
		}

		if err := syscall.Bind(fd, &ll); err != nil {
			return err
		}

		w.LogInfo("binding with success to iface %q (index %d)", iface.Name, iface.Index)
	}

	// set nano timestamp
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1)
	if err != nil {
		return err
	}

	filter := netutils.GetBpfFilterPort(w.GetConfig().Collectors.AfpacketLiveCapture.Port)
	err = netutils.ApplyBpfFilter(filter, fd)
	if err != nil {
		return err
	}

	w.LogInfo("BPF filter applied")

	w.fd = fd
	return nil
}

func (w *AfpacketSniffer) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	if w.fd == 0 {
		if err := w.Listen(); err != nil {
			w.LogError("init raw socket failed: %v\n", err)
			os.Exit(1) // nolint
		}
	}

	bufSize := w.GetConfig().Global.Worker.ChannelBufferSize
	if w.GetConfig().Collectors.AfpacketLiveCapture.ChannelBufferSize > 0 {
		bufSize = w.GetConfig().Collectors.AfpacketLiveCapture.ChannelBufferSize
	}
	dnsProcessor := NewDNSProcessor(w.GetConfig(), w.GetLogger(), w.GetName(), bufSize)
	dnsProcessor.SetDefaultRoutes(w.GetDefaultRoutes())
	dnsProcessor.SetDefaultDropped(w.GetDroppedRoutes())
	go dnsProcessor.StartCollect()

	dnsChan := make(chan netutils.DNSPacket)
	udpChan := make(chan gopacket.Packet)
	tcpChan := make(chan gopacket.Packet)
	fragIP4Chan := make(chan gopacket.Packet)
	fragIP6Chan := make(chan gopacket.Packet)

	netDecoder := &netutils.NetDecoder{}

	// defrag ipv4
	go netutils.IPDefragger(fragIP4Chan, udpChan, tcpChan, w.GetConfig().Collectors.AfpacketLiveCapture.Port)
	// defrag ipv6
	go netutils.IPDefragger(fragIP6Chan, udpChan, tcpChan, w.GetConfig().Collectors.AfpacketLiveCapture.Port)
	// tcp assembly
	go netutils.TCPAssembler(tcpChan, dnsChan, 0)
	// udp processor
	go netutils.UDPProcessor(udpChan, dnsChan, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func(ctx context.Context) {
		defer func() {
			dnsProcessor.Stop()
			netutils.RemoveBpfFilter(w.fd)
			syscall.Close(w.fd)
			w.LogInfo("read data terminated")
			defer close(done)
		}()

		buf := make([]byte, 65536)
		oob := make([]byte, 100)

		for {
			select {
			case <-ctx.Done():
				w.LogInfo("stopping sniffer...")
				syscall.Close(w.fd)
				return
			default:
				var fdSet syscall.FdSet
				fdSet.Bits[w.fd/64] |= 1 << (uint(w.fd) % 64)

				nReady, err := syscall.Select(w.fd+1, &fdSet, nil, nil, &syscall.Timeval{Sec: 1, Usec: 0})
				if err != nil {
					if errors.Is(err, syscall.EINTR) {
						continue
					}
					panic(err)
				}
				if nReady == 0 {
					continue
				}

				bufN, oobn, _, _, err := syscall.Recvmsg(w.fd, buf, oob, syscall.MSG_DONTWAIT)
				if err != nil {
					if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
						continue
					} else {
						w.LogFatal(pkgconfig.PrefixLogWorker+"["+w.GetName()+"read data", err)
					}
				}
				if bufN == 0 {
					w.LogFatal(pkgconfig.PrefixLogWorker + "[" + w.GetName() + "] buf empty")
				}
				if bufN > len(buf) {
					w.LogFatal(pkgconfig.PrefixLogWorker + "[" + w.GetName() + "] buf overflow")
				}
				if oobn == 0 {
					w.LogFatal(pkgconfig.PrefixLogWorker + "[" + w.GetName() + "] oob missing")
				}

				scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
				if err != nil {
					w.LogFatal(pkgconfig.PrefixLogWorker+"["+w.GetName()+"] control msg", err)
				}
				if len(scms) != 1 {
					continue
				}
				scm := scms[0]
				if scm.Header.Type != syscall.SCM_TIMESTAMPNS {
					w.LogFatal(pkgconfig.PrefixLogWorker + "[" + w.GetName() + "] scm timestampns missing")
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
					if !w.GetConfig().Collectors.AfpacketLiveCapture.FragmentSupport {
						continue
					}
					ip4 := packet.NetworkLayer().(*layers.IPv4)
					if ip4.Flags&layers.IPv4MoreFragments == 1 || ip4.FragOffset > 0 {
						fragIP4Chan <- packet
						continue
					}
				}

				// ipv6 fragmented packet ?
				if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
					if !w.GetConfig().Collectors.AfpacketLiveCapture.FragmentSupport {
						continue
					}
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
		case <-w.OnStop():
			w.LogInfo("stop to listen...")
			cancel()
			<-done
			return

		// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			// send the config to the dns processor
			dnsProcessor.NewConfig() <- cfg

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

			dm.DNSTap.Identity = w.GetConfig().GetServerIdentity()

			timestamp := dnsPacket.Timestamp.UnixNano()
			seconds := timestamp / int64(time.Second)
			dm.DNSTap.TimeSec = int(seconds)
			dm.DNSTap.TimeNsec = int(timestamp - seconds*int64(time.Second)*int64(time.Nanosecond))

			// send DNS message to DNS processor
			dnsProcessor.GetInputChannel() <- dm
		}
	}
}
