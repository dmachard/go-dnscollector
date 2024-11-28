package pkgconfig

import (
	"reflect"

	"github.com/creasty/defaults"
)

type ConfigCollectors struct {
	DNSMessage struct {
		Enable            bool `yaml:"enable" default:"false"`
		ChannelBufferSize int  `yaml:"chan-buffer-size" default:"0"`
		Matching          struct {
			Include map[string]interface{} `yaml:"include"`
			Exclude map[string]interface{} `yaml:"exclude"`
		} `yaml:"matching"`
	} `yaml:"dnsmessage"`
	Tail struct {
		Enable            bool   `yaml:"enable" default:"false"`
		TimeLayout        string `yaml:"time-layout" default:""`
		PatternQuery      string `yaml:"pattern-query" default:""`
		PatternReply      string `yaml:"pattern-reply" default:""`
		FilePath          string `yaml:"file-path" default:""`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"tail"`
	Dnstap struct {
		Enable            bool   `yaml:"enable" default:"false"`
		ListenIP          string `yaml:"listen-ip" default:"0.0.0.0"`
		ListenPort        int    `yaml:"listen-port" default:"6000"`
		SockPath          string `yaml:"sock-path" default:""`
		TLSSupport        bool   `yaml:"tls-support" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		RcvBufSize        int    `yaml:"sock-rcvbuf" default:"0"`
		ResetConn         bool   `yaml:"reset-conn" default:"true"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
		DisableDNSParser  bool   `yaml:"disable-dnsparser" default:"false"`
		ExtendedSupport   bool   `yaml:"extended-support" default:"false"`
		Compression       string `yaml:"compression" default:"none"`
	} `yaml:"dnstap"`
	DnstapProxifier struct {
		Enable            bool   `yaml:"enable" default:"false"`
		ListenIP          string `yaml:"listen-ip" default:"0.0.0.0"`
		ListenPort        int    `yaml:"listen-port" default:"6000"`
		SockPath          string `yaml:"sock-path" default:""`
		TLSSupport        bool   `yaml:"tls-support" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"dnstap-relay"`
	AfpacketLiveCapture struct {
		Enable            bool   `yaml:"enable" default:"false"`
		Port              int    `yaml:"port" default:"53"`
		Device            string `yaml:"device" default:""`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
		FragmentSupport   bool   `yaml:"enable-defrag-ip" default:"true"`
		GreSupport        bool   `yaml:"enable-gre" default:"false"`
	} `yaml:"afpacket-sniffer"`
	XdpLiveCapture struct {
		Enable            bool   `yaml:"enable" default:"false"`
		Port              int    `yaml:"port" default:"53"`
		Device            string `yaml:"device" default:""`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"xdp-sniffer"`
	PowerDNS struct {
		Enable            bool   `yaml:"enable" default:"false"`
		ListenIP          string `yaml:"listen-ip" default:"0.0.0.0"`
		ListenPort        int    `yaml:"listen-port" default:"6001"`
		TLSSupport        bool   `yaml:"tls-support" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		AddDNSPayload     bool   `yaml:"add-dns-payload" default:"false"`
		RcvBufSize        int    `yaml:"sock-rcvbuf" default:"0"`
		ResetConn         bool   `yaml:"reset-conn" default:"true"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"powerdns"`
	FileIngestor struct {
		Enable            bool   `yaml:"enable" default:"false"`
		WatchDir          string `yaml:"watch-dir" default:""`
		WatchMode         string `yaml:"watch-mode" default:"pcap"`
		PcapDNSPort       int    `yaml:"pcap-dns-port" default:"53"`
		DeleteAfter       bool   `yaml:"delete-after" default:"false"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"file-ingestor"`
	Tzsp struct {
		Enable            bool   `yaml:"enable" default:"false"`
		ListenIP          string `yaml:"listen-ip" default:"0.0.0.0"`
		ListenPort        int    `yaml:"listen-port" default:"10000"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"tzsp"`
}

func (c *ConfigCollectors) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigCollectors) IsValid(userCfg map[string]interface{}) error {
	return CheckConfigWithTags(reflect.ValueOf(*c), userCfg)
}

func (c *ConfigCollectors) GetNames() (ret []string) {
	cl := reflect.TypeOf(*c)

	for i := 0; i < cl.NumField(); i++ {
		field := cl.Field(i)
		tag := field.Tag.Get("yaml")
		ret = append(ret, tag)
	}
	return ret
}

func (c *ConfigCollectors) IsExists(name string) bool {
	tags := c.GetNames()
	for i := range tags {
		if name == tags[i] {
			return true
		}
	}
	return false
}
