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
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/tzsp"
)

type TzspSniffer struct {
	done     chan bool
	exit     chan bool
	listen   net.UDPConn
	loggers  []dnsutils.Worker
	config   *dnsutils.Config
	logger   *logger.Logger
	name     string
	identity string
	port     int
	ip       string
}

func NewTzsp(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *TzspSniffer {
	logger.Info("[%s] tzsp collector - enabled", name)
	s := &TzspSniffer{
		done:    make(chan bool),
		exit:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
		name:    name,
	}
	s.ReadConfig()
	return s
}

func (c *TzspSniffer) GetName() string { return c.name }

func (c *TzspSniffer) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *TzspSniffer) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *TzspSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] tzsp collector - "+msg, v...)
}

func (c *TzspSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] tzsp collector - "+msg, v...)
}

func (c *TzspSniffer) ReadConfig() {

	c.port = c.config.Collectors.Tzsp.ListenPort
	c.ip = c.config.Collectors.Tzsp.ListenIp
	c.identity = c.config.GetServerIdentity()
	// TODO: Implement
}

func (c *TzspSniffer) Listen() error {
	c.logger.Info("running in background...")

	ServerAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.ip, c.port))
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

func (c *TzspSniffer) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *TzspSniffer) Stop() {
	c.LogInfo("stopping...")

	// Finally close the listener to unblock accept
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *TzspSniffer) Run() {
	c.logger.Info("starting collector...")

	if err := c.Listen(); err != nil {
		c.logger.Fatal("collector tzsp listening failed: ", err)
	}

	dnsProcessor := NewDnsProcessor(c.config, c.logger, c.name)

	go dnsProcessor.Run(c.Loggers())

	go func() {
		buf := make([]byte, 65536)
		oob := make([]byte, 100)
		for {
			//flags, from
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

			tzsp_packet, err := tzsp.Parse(pkt)

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
			parser.DecodeLayers(tzsp_packet.Data, &decodedLayers)

			dm := dnsutils.DnsMessage{}
			dm.Init()

			ignore_packet := false
			for _, layertyp := range decodedLayers {
				switch layertyp {
				case layers.LayerTypeIPv4:
					dm.NetworkInfo.Family = dnsutils.PROTO_IPV4
					dm.NetworkInfo.QueryIp = ip4.SrcIP.String()
					dm.NetworkInfo.ResponseIp = ip4.DstIP.String()

				case layers.LayerTypeIPv6:
					dm.NetworkInfo.QueryIp = ip6.SrcIP.String()
					dm.NetworkInfo.ResponseIp = ip6.DstIP.String()
					dm.NetworkInfo.Family = dnsutils.PROTO_IPV6

				case layers.LayerTypeUDP:
					dm.NetworkInfo.QueryPort = fmt.Sprint(int(udp.SrcPort))
					dm.NetworkInfo.ResponsePort = fmt.Sprint(int(udp.DstPort))
					dm.DNS.Payload = udp.Payload
					dm.DNS.Length = len(udp.Payload)
					dm.NetworkInfo.Protocol = dnsutils.PROTO_UDP

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
						ignore_packet = true
						continue
					}

					dm.NetworkInfo.QueryPort = fmt.Sprint(int(tcp.SrcPort))
					dm.NetworkInfo.ResponsePort = fmt.Sprint(int(tcp.DstPort))
					dm.DNS.Payload = tcp.Payload[2:]
					dm.DNS.Length = len(tcp.Payload[2:])
					dm.NetworkInfo.Protocol = dnsutils.PROTO_TCP
				}
			}

			if !ignore_packet {
				dm.DnsTap.Identity = c.identity

				// set timestamp
				dm.DnsTap.TimeSec = int(tsec)
				dm.DnsTap.TimeNsec = int(nsec)

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
