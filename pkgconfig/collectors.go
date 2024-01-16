package pkgconfig

import "reflect"

type ConfigCollectors struct {
	DNSMessage struct {
		Enable            bool `yaml:"enable"`
		ChannelBufferSize int  `yaml:"chan-buffer-size"`
		Matching          struct {
			Include map[string]interface{} `yaml:"include"`
			Exclude map[string]interface{} `yaml:"exclude"`
		} `yaml:"matching"`
	} `yaml:"dnsmessage"`
	Tail struct {
		Enable       bool   `yaml:"enable"`
		TimeLayout   string `yaml:"time-layout"`
		PatternQuery string `yaml:"pattern-query"`
		PatternReply string `yaml:"pattern-reply"`
		FilePath     string `yaml:"file-path"`
	} `yaml:"tail"`
	Dnstap struct {
		Enable            bool   `yaml:"enable"`
		ListenIP          string `yaml:"listen-ip"`
		ListenPort        int    `yaml:"listen-port"`
		SockPath          string `yaml:"sock-path"`
		TLSSupport        bool   `yaml:"tls-support"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		RcvBufSize        int    `yaml:"sock-rcvbuf"`
		ResetConn         bool   `yaml:"reset-conn"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
		DisableDNSParser  bool   `yaml:"disable-dnsparser"`
	} `yaml:"dnstap"`
	DnstapProxifier struct {
		Enable        bool   `yaml:"enable"`
		ListenIP      string `yaml:"listen-ip"`
		ListenPort    int    `yaml:"listen-port"`
		SockPath      string `yaml:"sock-path"`
		TLSSupport    bool   `yaml:"tls-support"`
		TLSMinVersion string `yaml:"tls-min-version"`
		CertFile      string `yaml:"cert-file"`
		KeyFile       string `yaml:"key-file"`
	} `yaml:"dnstap-relay"`
	AfpacketLiveCapture struct {
		Enable            bool   `yaml:"enable"`
		Port              int    `yaml:"port"`
		Device            string `yaml:"device"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"afpacket-sniffer"`
	XdpLiveCapture struct {
		Enable            bool   `yaml:"enable"`
		Port              int    `yaml:"port"`
		Device            string `yaml:"device"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"xdp-sniffer"`
	PowerDNS struct {
		Enable            bool   `yaml:"enable"`
		ListenIP          string `yaml:"listen-ip"`
		ListenPort        int    `yaml:"listen-port"`
		TLSSupport        bool   `yaml:"tls-support"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		AddDNSPayload     bool   `yaml:"add-dns-payload"`
		RcvBufSize        int    `yaml:"sock-rcvbuf"`
		ResetConn         bool   `yaml:"reset-conn"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"powerdns"`
	FileIngestor struct {
		Enable            bool   `yaml:"enable"`
		WatchDir          string `yaml:"watch-dir"`
		WatchMode         string `yaml:"watch-mode"`
		PcapDNSPort       int    `yaml:"pcap-dns-port"`
		DeleteAfter       bool   `yaml:"delete-after"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"file-ingestor"`
	Tzsp struct {
		Enable            bool   `yaml:"enable"`
		ListenIP          string `yaml:"listen-ip"`
		ListenPort        int    `yaml:"listen-port"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"tzsp"`
}

func (c *ConfigCollectors) SetDefault() {
	c.DNSMessage.Enable = false
	c.DNSMessage.ChannelBufferSize = 65535

	c.Tail.Enable = false
	c.Tail.TimeLayout = ""
	c.Tail.PatternQuery = ""
	c.Tail.PatternReply = ""
	c.Tail.FilePath = ""

	c.Dnstap.Enable = false
	c.Dnstap.ListenIP = AnyIP
	c.Dnstap.ListenPort = 6000
	c.Dnstap.SockPath = ""
	c.Dnstap.TLSSupport = false
	c.Dnstap.TLSMinVersion = TLSV12
	c.Dnstap.CertFile = ""
	c.Dnstap.KeyFile = ""
	c.Dnstap.RcvBufSize = 0
	c.Dnstap.ResetConn = true
	c.Dnstap.ChannelBufferSize = 65535
	c.Dnstap.DisableDNSParser = false

	c.DnstapProxifier.Enable = false
	c.DnstapProxifier.ListenIP = AnyIP
	c.DnstapProxifier.ListenPort = 6000
	c.DnstapProxifier.SockPath = ""
	c.DnstapProxifier.TLSSupport = false
	c.DnstapProxifier.TLSMinVersion = TLSV12
	c.DnstapProxifier.CertFile = ""
	c.DnstapProxifier.KeyFile = ""

	c.XdpLiveCapture.Enable = false
	c.XdpLiveCapture.Device = ""
	c.XdpLiveCapture.ChannelBufferSize = 65535

	c.AfpacketLiveCapture.Enable = false
	c.AfpacketLiveCapture.Port = 53
	c.AfpacketLiveCapture.Device = ""
	c.AfpacketLiveCapture.ChannelBufferSize = 65535

	c.PowerDNS.Enable = false
	c.PowerDNS.ListenIP = AnyIP
	c.PowerDNS.ListenPort = 6001
	c.PowerDNS.TLSSupport = false
	c.PowerDNS.TLSMinVersion = TLSV12
	c.PowerDNS.CertFile = ""
	c.PowerDNS.KeyFile = ""
	c.PowerDNS.AddDNSPayload = false
	c.PowerDNS.RcvBufSize = 0
	c.PowerDNS.ResetConn = true
	c.PowerDNS.ChannelBufferSize = 65535

	c.FileIngestor.Enable = false
	c.FileIngestor.WatchDir = ""
	c.FileIngestor.PcapDNSPort = 53
	c.FileIngestor.WatchMode = ModePCAP
	c.FileIngestor.DeleteAfter = false
	c.FileIngestor.ChannelBufferSize = 65535

	c.Tzsp.Enable = false
	c.Tzsp.ListenIP = AnyIP
	c.Tzsp.ListenPort = 10000
	c.Tzsp.ChannelBufferSize = 65535
}

func (c *ConfigCollectors) GetTags() (ret []string) {
	cl := reflect.TypeOf(*c)

	for i := 0; i < cl.NumField(); i++ {
		field := cl.Field(i)
		tag := field.Tag.Get("yaml")
		ret = append(ret, tag)
	}
	return ret
}

func (c *ConfigCollectors) IsValid(name string) bool {
	tags := c.GetTags()
	for i := range tags {
		if name == tags[i] {
			return true
		}
	}
	return false
}
