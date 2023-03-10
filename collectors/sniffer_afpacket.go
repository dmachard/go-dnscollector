//go:build linux
// +build linux

package collectors

import (
	"encoding/binary"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Convert a uint16 to host byte order (big endian)
func Htons(v uint16) int {
	return int((v << 8) | (v >> 8))
}

func GetBpfFilter_Ingress(port int) []bpf.Instruction {
	// bpf filter: (ip  or ip6 ) and (udp or tcp) and port 53
	// fragmented packets are ignored
	var filter = []bpf.Instruction{
		// Load eth.type (2 bytes at offset 12) and push-it in register A
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// if eth.type == IPv4 continue with the next instruction
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 8},
		// Load ip.proto (1 byte at offset 23) and push-it in register A
		bpf.LoadAbsolute{Off: 23, Size: 1},
		// ip.proto == UDP ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 1, SkipFalse: 0},
		// ip.proto == TCP ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 0, SkipFalse: 12},
		// load flags and fragment offset (2 bytes at offset 20) to ignore fragmented packet
		bpf.LoadAbsolute{Off: 20, Size: 2},
		// Only look at the last 13 bits of the data saved in regiter A
		//  0x1fff == 0001 1111 1111 1111 (fragment offset)
		// If any of the data in fragment offset is true, ignore the packet
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 10, SkipFalse: 0},
		// Load ip.length
		// Register X = ip header len * 4
		bpf.LoadMemShift{Off: 14},
		// Load source port in tcp or udp (2 bytes at offset x+14)
		bpf.LoadIndirect{Off: 14, Size: 2},
		// source port equal to 53 ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 6, SkipFalse: 7},
		// if eth.type == IPv6 continue with the next instruction
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 0, SkipFalse: 6},
		// Load ipv6.nxt (2 bytes at offset 12) and push-it in register A
		bpf.LoadAbsolute{Off: 20, Size: 1},
		// ip.proto == UDP ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 1, SkipFalse: 0},
		// ip.proto == TCP ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 0, SkipFalse: 3},
		// Load source port tcp or udp (2 bytes at offset 54)
		bpf.LoadAbsolute{Off: 54, Size: 2},
		// source port equal to 53 ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 0, SkipFalse: 1},
		// Keep the packet and send up to 65k of the packet to userspace
		bpf.RetConstant{Val: 0xFFFF},
		// Ignore packet
		bpf.RetConstant{Val: 0},
	}
	return filter
}

func GetBpfFilter(port int) []bpf.Instruction {
	// bpf filter: (ip  or ip6 ) and (udp or tcp) and port 53
	// fragmented packets are ignored
	var filter = []bpf.Instruction{
		// Load eth.type (2 bytes at offset 12) and push-it in register A
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// if eth.type == IPv4 continue with the next instruction
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 10},
		// Load ip.proto (1 byte at offset 23) and push-it in register A
		bpf.LoadAbsolute{Off: 23, Size: 1},
		// ip.proto == UDP ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 1, SkipFalse: 0},
		// ip.proto == TCP ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 0, SkipFalse: 16},
		// load flags and fragment offset (2 bytes at offset 20) to ignore fragmented packet
		bpf.LoadAbsolute{Off: 20, Size: 2},
		// Only look at the last 13 bits of the data saved in regiter A
		//  0x1fff == 0001 1111 1111 1111 (fragment offset)
		// If any of the data in fragment offset is true, ignore the packet
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 14, SkipFalse: 0},
		// Load ip.length
		// Register X = ip header len * 4
		bpf.LoadMemShift{Off: 14},
		// Load source port in tcp or udp (2 bytes at offset x+14)
		bpf.LoadIndirect{Off: 14, Size: 2},
		// source port equal to 53 ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 10, SkipFalse: 0},
		// Load destination port in tcp or udp  (2 bytes at offset x+16)
		bpf.LoadIndirect{Off: 16, Size: 2},
		// destination port equal to 53 ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 8, SkipFalse: 9},
		// if eth.type == IPv6 continue with the next instruction
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 0, SkipFalse: 8},
		// Load ipv6.nxt (2 bytes at offset 12) and push-it in register A
		bpf.LoadAbsolute{Off: 20, Size: 1},
		// ip.proto == UDP ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 1, SkipFalse: 0},
		// ip.proto == TCP ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 0, SkipFalse: 5},
		// Load source port tcp or udp (2 bytes at offset 54)
		bpf.LoadAbsolute{Off: 54, Size: 2},
		// source port equal to 53 ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 2, SkipFalse: 0},
		// Load destination port tcp or udp (2 bytes at offset 56)
		bpf.LoadAbsolute{Off: 56, Size: 2},
		// destination port equal to 53 ?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 0, SkipFalse: 1},
		// Keep the packet and send up to 65k of the packet to userspace
		bpf.RetConstant{Val: 0xFFFF},
		// Ignore packet
		bpf.RetConstant{Val: 0},
	}
	return filter
}

func ApplyBpfFilter(filter []bpf.Instruction, fd int) (err error) {
	var assembled []bpf.RawInstruction
	if assembled, err = bpf.Assemble(filter); err != nil {
		return err
	}

	prog := &unix.SockFprog{
		Len:    uint16(len(assembled)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&assembled[0])),
	}

	return unix.SetsockoptSockFprog(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, prog)
}

func RemoveBpfFilter(fd int) (err error) {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DETACH_FILTER, 0)
}

type AfpacketSniffer struct {
	done     chan bool
	exit     chan bool
	fd       int
	port     int
	device   string
	identity string
	loggers  []dnsutils.Worker
	config   *dnsutils.Config
	logger   *logger.Logger
	name     string
}

func NewAfpacketSniffer(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	logger.Info("[%s] AFPACKET collector - enabled", name)
	s := &AfpacketSniffer{
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

func (c *AfpacketSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] AFPACKET collector - "+msg, v...)
}

func (c *AfpacketSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] AFPACKET collector - "+msg, v...)
}

func (c *AfpacketSniffer) GetName() string { return c.name }

func (c *AfpacketSniffer) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *AfpacketSniffer) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *AfpacketSniffer) ReadConfig() {
	c.port = c.config.Collectors.AfpacketLiveCapture.Port
	c.identity = c.config.GetServerIdentity()
	c.device = c.config.Collectors.AfpacketLiveCapture.Device
}

func (c *AfpacketSniffer) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *AfpacketSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *AfpacketSniffer) Listen() error {
	// raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, Htons(syscall.ETH_P_ALL))
	if err != nil {
		return err
	}

	// bind to device ?
	if c.device != "" {
		iface, err := net.InterfaceByName(c.device)
		if err != nil {
			return err
		}

		ll := syscall.SockaddrLinklayer{
			Ifindex: iface.Index,
		}

		if err := syscall.Bind(fd, &ll); err != nil {
			return err
		}

		c.LogInfo("Binding with success to iface %q (index %d)", iface.Name, iface.Index)
	}

	// set nano timestamp
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1)
	if err != nil {
		return err
	}

	filter := GetBpfFilter(c.port)
	//filter := GetBpfFilter_Ingress(c.port)
	err = ApplyBpfFilter(filter, fd)
	if err != nil {
		return err
	}

	c.LogInfo("BPF filter applied")

	c.fd = fd
	return nil
}

func (c *AfpacketSniffer) Run() {
	c.LogInfo("starting collector...")
	defer RemoveBpfFilter(c.fd)
	defer syscall.Close(c.fd)

	if c.fd == 0 {
		if err := c.Listen(); err != nil {
			c.LogError("init raw socket failed: %v\n", err)
			os.Exit(1)
		}
	}

	dnsProcessor := NewDnsProcessor(c.config, c.logger, c.name)
	dnsProcessor.cacheSupport = c.config.Collectors.AfpacketLiveCapture.CacheSupport
	dnsProcessor.queryTimeout = c.config.Collectors.AfpacketLiveCapture.QueryTimeout
	go dnsProcessor.Run(c.Loggers())

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var ipFlow gopacket.Flow
	var tcp layers.TCP
	var udp layers.UDP
	parserLayers := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	reassembleChan := make(chan netlib.DnsPacket)

	streamFactory := &netlib.DnsStreamFactory{Reassembled: reassembleChan}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	ticker := time.NewTicker(time.Minute * 1)

	// goroutine to read all packets reassembled
	go func() {
		// prepare dns message
		dm := dnsutils.DnsMessage{}

		for {
			select {
			// read packet from channel
			case dnsPacket := <-reassembleChan:
				// reset
				dm.Init()

				dm.NetworkInfo.Family = dnsPacket.IpLayer.EndpointType().String()
				dm.NetworkInfo.QueryIp = dnsPacket.IpLayer.Src().String()
				dm.NetworkInfo.ResponseIp = dnsPacket.IpLayer.Dst().String()
				dm.NetworkInfo.QueryPort = dnsPacket.TransportLayer.Src().String()
				dm.NetworkInfo.ResponsePort = dnsPacket.TransportLayer.Dst().String()
				dm.NetworkInfo.Protocol = dnsPacket.TransportLayer.EndpointType().String()

				dm.DNS.Payload = dnsPacket.Payload
				dm.DNS.Length = len(dnsPacket.Payload)

				dm.DnsTap.Identity = c.identity
				dm.DnsTap.TimeSec = dnsPacket.Timestamp.Second()
				dm.DnsTap.TimeNsec = int(dnsPacket.Timestamp.UnixNano())

				// send DNS message to DNS processor
				dnsProcessor.GetChannel() <- dm

			case <-ticker.C:
				// Every minute, flush connections that haven't seen activity in the past 2 minutes.
				assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
			}
		}
	}()

	go func() {
		buf := make([]byte, 65536)
		oob := make([]byte, 100)
		for {
			//flags, from
			bufN, oobn, _, _, err := syscall.Recvmsg(c.fd, buf, oob, 0)
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

			scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				panic(err)
			}
			if len(scms) != 1 {
				continue
			}
			scm := scms[0]
			if scm.Header.Type != syscall.SCM_TIMESTAMPNS {
				panic("scm timestampns missing")
			}
			tsec := binary.LittleEndian.Uint32(scm.Data[:4])
			nsec := binary.LittleEndian.Uint32(scm.Data[8:12])
			timestamp := time.Unix(int64(tsec), int64(nsec))

			// decode layers
			parserLayers.DecodeLayers(buf[:bufN], &decodedLayers)
			if len(ip4.Contents) > 0 {
				ipFlow = ip4.NetworkFlow()
			}
			if len(ip6.Contents) > 0 {
				ipFlow = ip6.NetworkFlow()
			}

			for _, layerType := range decodedLayers {
				if layerType == layers.LayerTypeUDP {
					reassembleChan <- netlib.DnsPacket{
						Payload:        udp.Payload,
						IpLayer:        ipFlow,
						TransportLayer: udp.TransportFlow(),
						Timestamp:      timestamp,
					}
				}
				if layerType == layers.LayerTypeTCP {
					assembler.AssembleWithTimestamp(
						ipFlow,
						&tcp,
						timestamp,
					)
				}
			}
		}

	}()

	<-c.exit

	// stop dns processor
	dnsProcessor.Stop()

	c.LogInfo("run terminated")
	c.done <- true
}
