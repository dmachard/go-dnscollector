package pkgconfig

type ConfigCollectors struct {
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
	} `yaml:"dnstap-proxifier"`
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
