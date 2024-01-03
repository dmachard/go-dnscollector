//go:build linux
// +build linux

// Written by Noel Kuntze <noel.kuntze {@@@@@} thermi.consulting>

package collectors

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/tzsp"
)

type TZSPSniffer struct {
	done          chan bool
	exit          chan bool
	listen        net.UDPConn
	defaultRoutes []dnsutils.Worker
	config        *pkgconfig.Config
	logger        *logger.Logger
	name          string
	identity      string
}

func NewTZSP(loggers []dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *TZSPSniffer {
	logger.Info("[%s] collector=tzsp - enabled", name)
	s := &TZSPSniffer{
		done:          make(chan bool),
		exit:          make(chan bool),
		config:        config,
		defaultRoutes: loggers,
		logger:        logger,
		name:          name,
	}
	s.ReadConfig()
	return s
}

func (c *TZSPSniffer) GetName() string { return c.name }

func (c *TZSPSniffer) AddDroppedRoute(wrk dnsutils.Worker) {
	// TODO
}

func (c *TZSPSniffer) AddDefaultRoute(wrk dnsutils.Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *TZSPSniffer) SetLoggers(loggers []dnsutils.Worker) {
	c.defaultRoutes = loggers
}

func (c *TZSPSniffer) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	channels := []chan dnsutils.DNSMessage{}
	names := []string{}
	for _, p := range c.defaultRoutes {
		channels = append(channels, p.Channel())
		names = append(names, p.GetName())
	}
	return channels, names
}

func (c *TZSPSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] collector=tzsp  "+msg, v...)
}

func (c *TZSPSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] collector=tzsp - "+msg, v...)
}

func (c *TZSPSniffer) ReadConfig() {
	c.identity = c.config.GetServerIdentity()
}

func (c *TZSPSniffer) ReloadConfig(config *pkgconfig.Config) {
	// TODO implement reload configuration
}

func (c *TZSPSniffer) Listen() error {
	c.logger.Info("running in background...")

	ServerAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.config.Collectors.Tzsp.ListenIP, c.config.Collectors.Tzsp.ListenPort))
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
	c.LogInfo("is listening on %s", ServerConn.LocalAddr())
	c.listen = *ServerConn
	return nil
}

func (c *TZSPSniffer) Channel() chan dnsutils.DNSMessage {
	return nil
}

func (c *TZSPSniffer) Stop() {
	c.LogInfo("stopping...")

	// Finally close the listener to unblock accept
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *TZSPSniffer) Run() {
	c.logger.Info("starting collector...")

	if err := c.Listen(); err != nil {
		c.logger.Fatal("collector=tzsp listening failed: ", err)
	}

	dnsProcessor := processors.NewDNSProcessor(c.config, c.logger, c.name, c.config.Collectors.Tzsp.ChannelBufferSize)
	go dnsProcessor.Run(c.Loggers())

	go func() {
		buf := make([]byte, 65536)
		oob := make([]byte, 100)
		for {
			// flags, from
			bufN, oobn, _, _, err := c.listen.ReadMsgUDPAddrPort(buf, oob)
			if err != nil {
				panic(err)
			}
			if bufN == 0 {
				panic("buf empty")
			}
			if bufN > len(buf) {
				panic("buf overflow")
			}
			if oobn == 0 {
				panic("oob missing")
			}
			c.LogInfo("Packet received")
			scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				panic(err)
			}
			if len(scms) != 1 {
				c.LogInfo("len(scms) != 1")
				continue
			}
			scm := scms[0]
			if scm.Header.Type != syscall.SCM_TIMESTAMPNS {
				panic("scm timestampns missing")
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
					dm.NetworkInfo.Family = netlib.ProtoIPv4
					dm.NetworkInfo.QueryIP = ip4.SrcIP.String()
					dm.NetworkInfo.ResponseIP = ip4.DstIP.String()

				case layers.LayerTypeIPv6:
					dm.NetworkInfo.QueryIP = ip6.SrcIP.String()
					dm.NetworkInfo.ResponseIP = ip6.DstIP.String()
					dm.NetworkInfo.Family = netlib.ProtoIPv6

				case layers.LayerTypeUDP:
					dm.NetworkInfo.QueryPort = fmt.Sprint(int(udp.SrcPort))
					dm.NetworkInfo.ResponsePort = fmt.Sprint(int(udp.DstPort))
					dm.DNS.Payload = udp.Payload
					dm.DNS.Length = len(udp.Payload)
					dm.NetworkInfo.Protocol = netlib.ProtoUDP

				case layers.LayerTypeTCP:
					// ignore SYN/ACK packet
					// Note: disabled because SYN/SYN+Ack might contain data if TCP Fast open is used
					// if !tcp.PSH {
					// 	ignore_packet = true
					// 	continue
					// }
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
					dm.NetworkInfo.Protocol = netlib.ProtoTCP
				}
			}

			if !ignorePacket {
				dm.DNSTap.Identity = c.identity

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
	}()

	<-c.exit

	// stop dns processor
	dnsProcessor.Stop()

	c.LogInfo("run terminated")
	c.done <- true
}
