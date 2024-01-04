//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package collectors

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-dnscollector/xdp"
	"github.com/dmachard/go-logger"
	"golang.org/x/sys/unix"
)

func GetIPAddress[T uint32 | [4]uint32](ip T, mapper func(T) net.IP) net.IP {
	return mapper(ip)
}

func ConvertIP4(ip uint32) net.IP {
	addr := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(addr, ip)
	return addr
}

func ConvertIP6(ip [4]uint32) net.IP {
	addr := make(net.IP, net.IPv6len)
	binary.LittleEndian.PutUint32(addr[0:], ip[0])
	binary.LittleEndian.PutUint32(addr[4:], ip[1])
	binary.LittleEndian.PutUint32(addr[8:], ip[2])
	binary.LittleEndian.PutUint32(addr[12:], ip[3])
	return addr
}

type XDPSniffer struct {
	done          chan bool
	exit          chan bool
	identity      string
	defaultRoutes []pkgutils.Worker
	config        *pkgconfig.Config
	configChan    chan *pkgconfig.Config
	logger        *logger.Logger
	name          string
}

func NewXDPSniffer(loggers []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *XDPSniffer {
	logger.Info("[%s] collector=xdp - enabled", name)
	s := &XDPSniffer{
		done:          make(chan bool),
		exit:          make(chan bool),
		config:        config,
		configChan:    make(chan *pkgconfig.Config),
		defaultRoutes: loggers,
		logger:        logger,
		name:          name,
	}
	s.ReadConfig()
	return s
}

func (c *XDPSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] collector=xdp - "+msg, v...)
}

func (c *XDPSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] collector=xdp - "+msg, v...)
}

func (c *XDPSniffer) GetName() string { return c.name }

func (c *XDPSniffer) AddDroppedRoute(wrk pkgutils.Worker) {
	// TODO
}

func (c *XDPSniffer) AddDefaultRoute(wrk pkgutils.Worker) {
	c.defaultRoutes = append(c.defaultRoutes, wrk)
}

func (c *XDPSniffer) SetLoggers(loggers []pkgutils.Worker) {
	c.defaultRoutes = loggers
}

func (c *XDPSniffer) Loggers() ([]chan dnsutils.DNSMessage, []string) {
	return pkgutils.GetActiveRoutes(c.defaultRoutes)
}

func (c *XDPSniffer) ReadConfig() {
	c.identity = c.config.GetServerIdentity()
}

func (c *XDPSniffer) ReloadConfig(config *pkgconfig.Config) {
	c.LogInfo("reload configuration...")
	c.configChan <- config
}

func (c *XDPSniffer) GetInputChannel() chan dnsutils.DNSMessage {
	return nil
}

func (c *XDPSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *XDPSniffer) Run() {
	c.LogInfo("starting collector...")

	dnsProcessor := processors.NewDNSProcessor(c.config, c.logger, c.name, c.config.Collectors.XdpLiveCapture.ChannelBufferSize)
	go dnsProcessor.Run(c.Loggers())

	iface, err := net.InterfaceByName(c.config.Collectors.XdpLiveCapture.Device)
	if err != nil {
		c.LogError("lookup network iface: %s", err)
		os.Exit(1)
	}

	// Load pre-compiled programs into the kernel.
	objs := xdp.BpfObjects{}
	if err := xdp.LoadBpfObjects(&objs, nil); err != nil {
		c.LogError("loading BPF objects: %s", err)
		os.Exit(1)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpSniffer,
		Interface: iface.Index,
	})
	if err != nil {
		c.LogError("could not attach XDP program: %s", err)
		os.Exit(1) // nolint
	}
	defer l.Close()

	c.LogInfo("XDP program attached to iface %q (index %d)", iface.Name, iface.Index)

	perfEvent, err := perf.NewReader(objs.Pkts, 1<<24)
	if err != nil {
		panic(err)
	}

	dnsChan := make(chan dnsutils.DNSMessage)

	// goroutine to read all packets reassembled
	go func() {
		for {
			select {
			// new config provided?
			case cfg, opened := <-c.configChan:
				if !opened {
					return
				}
				c.config = cfg
				c.ReadConfig()

				// send the config to the dns processor
				dnsProcessor.ConfigChan <- cfg

			// dns message to read ?
			case dm := <-dnsChan:

				// update identity with config ?
				dm.DNSTap.Identity = c.identity

				dnsProcessor.GetChannel() <- dm

			}
		}
	}()

	go func() {
		var pkt xdp.BpfPktEvent
		for {
			// The data submitted via bpf_perf_event_output.
			record, err := perfEvent.Read()
			if err != nil {
				c.LogError("BPF reading map: %s", err)
				break
			}

			if record.LostSamples != 0 {
				c.LogError("BPF dump: Dropped %d samples from kernel perf buffer", record.LostSamples)
				continue
			}

			reader := bytes.NewReader(record.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, &pkt); err != nil {
				c.LogError("BPF reading sample: %s", err)
				break
			}

			// adjust arrival time
			timenow := time.Now().UTC()
			var ts unix.Timespec
			unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
			elapsed := time.Since(timenow) * time.Nanosecond
			delta3 := time.Duration(uint64(unix.TimespecToNsec(ts))-pkt.Timestamp) * time.Nanosecond
			tsAdjusted := timenow.Add(-(delta3 + elapsed))

			// convert ip
			var saddr, daddr net.IP
			if pkt.IpVersion == 0x0800 {
				saddr = GetIPAddress(pkt.SrcAddr, ConvertIP4)
				daddr = GetIPAddress(pkt.DstAddr, ConvertIP4)
			} else {
				saddr = GetIPAddress(pkt.SrcAddr6, ConvertIP6)
				daddr = GetIPAddress(pkt.DstAddr6, ConvertIP6)
			}

			// prepare DnsMessage
			dm := dnsutils.DNSMessage{}
			dm.Init()

			dm.DNSTap.TimeSec = int(tsAdjusted.Unix())
			dm.DNSTap.TimeNsec = int(tsAdjusted.UnixNano() - tsAdjusted.Unix()*1e9)

			if pkt.SrcPort == 53 {
				dm.DNSTap.Operation = dnsutils.DNSTapClientResponse
			} else {
				dm.DNSTap.Operation = dnsutils.DNSTapClientQuery
			}

			dm.NetworkInfo.QueryIP = saddr.String()
			dm.NetworkInfo.QueryPort = fmt.Sprint(pkt.SrcPort)
			dm.NetworkInfo.ResponseIP = daddr.String()
			dm.NetworkInfo.ResponsePort = fmt.Sprint(pkt.DstPort)

			if pkt.IpVersion == 0x0800 {
				dm.NetworkInfo.Family = netlib.ProtoIPv4
			} else {
				dm.NetworkInfo.Family = netlib.ProtoIPv6
			}

			if pkt.IpProto == 0x11 {
				dm.NetworkInfo.Protocol = netlib.ProtoUDP
				dm.DNS.Payload = record.RawSample[int(pkt.PktOffset)+int(pkt.PayloadOffset):]
				dm.DNS.Length = len(dm.DNS.Payload)
			} else {
				dm.NetworkInfo.Protocol = netlib.ProtoTCP
				dm.DNS.Payload = record.RawSample[int(pkt.PktOffset)+int(pkt.PayloadOffset)+2:]
				dm.DNS.Length = len(dm.DNS.Payload)
			}

			dnsChan <- dm
		}
	}()

	<-c.exit
	close(dnsChan)
	close(c.configChan)

	// stop dns processor
	dnsProcessor.Stop()

	c.LogInfo("run terminated")
	c.done <- true
}
