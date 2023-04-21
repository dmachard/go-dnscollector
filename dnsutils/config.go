package dnsutils

import (
	"os"

	"gopkg.in/yaml.v3"
)

func IsValidMode(mode string) bool {
	switch mode {
	case
		MODE_TEXT,
		MODE_JSON,
		MODE_FLATJSON:
		return true
	}
	return false
}

func IsValidTLS(mode string) bool {
	switch mode {
	case
		TLS_v10,
		TLS_v11,
		TLS_v12,
		TLS_v13:
		return true
	}
	return false
}

type MultiplexInOut struct {
	Name       string                 `yaml:"name"`
	Transforms map[string]interface{} `yaml:"transforms"`
	Params     map[string]interface{} `yaml:",inline"`
}

type MultiplexRoutes struct {
	Src []string `yaml:"from,flow"`
	Dst []string `yaml:"to,flow"`
}

type ConfigTransformers struct {
	UserPrivacy struct {
		Enable        bool `yaml:"enable"`
		AnonymizeIP   bool `yaml:"anonymize-ip"`
		MinimazeQname bool `yaml:"minimaze-qname"`
		HashIP        bool `yaml:"hash-ip"`
	} `yaml:"user-privacy"`
	Normalize struct {
		Enable         bool `yaml:"enable"`
		QnameLowerCase bool `yaml:"qname-lowercase"`
		QuietText      bool `yaml:"quiet-text"`
		AddTld         bool `yaml:"add-tld"`
		AddTldPlusOne  bool `yaml:"add-tld-plus-one"`
	} `yaml:"normalize"`
	Latency struct {
		Enable            bool `yaml:"enable"`
		MeasureLatency    bool `yaml:"measure-latency"`
		UnansweredQueries bool `yaml:"unanswered-queries"`
		QueriesTimeout    int  `yaml:"queries-timeout"`
	}
	Reducer struct {
		Enable                    bool `yaml:"enable"`
		RepetitiveTrafficDetector bool `yaml:"repetitive-traffic-detector"`
		WatchInterval             int  `yaml:"watch-interval"`
	}
	Filtering struct {
		Enable          bool     `yaml:"enable"`
		DropFqdnFile    string   `yaml:"drop-fqdn-file"`
		DropDomainFile  string   `yaml:"drop-domain-file"`
		KeepFqdnFile    string   `yaml:"keep-fqdn-file"`
		KeepDomainFile  string   `yaml:"keep-domain-file"`
		DropQueryIpFile string   `yaml:"drop-queryip-file"`
		KeepQueryIpFile string   `yaml:"keep-queryip-file"`
		DropRcodes      []string `yaml:"drop-rcodes,flow"`
		LogQueries      bool     `yaml:"log-queries"`
		LogReplies      bool     `yaml:"log-replies"`
		Downsample      int      `yaml:"downsample"`
	} `yaml:"filtering"`
	GeoIP struct {
		Enable        bool   `yaml:"enable"`
		DbCountryFile string `yaml:"mmdb-country-file"`
		DbCityFile    string `yaml:"mmdb-city-file"`
		DbAsnFile     string `yaml:"mmdb-asn-file"`
	} `yaml:"geoip"`
	Suspicious struct {
		Enable             bool     `yaml:"enable"`
		ThresholdQnameLen  int      `yaml:"threshold-qname-len"`
		ThresholdPacketLen int      `yaml:"threshold-packet-len"`
		ThresholdSlow      float64  `yaml:"threshold-slow"`
		CommonQtypes       []string `yaml:"common-qtypes,flow"`
		UnallowedChars     []string `yaml:"unallowed-chars,flow"`
		ThresholdMaxLabels int      `yaml:"threshold-max-labels"`
	} `yaml:"suspicious"`
	Extract struct {
		Enable     bool `yaml:"enable"`
		AddPayload bool `yaml:"add-payload"`
	} `yaml:"extract"`
}

func (c *ConfigTransformers) SetDefault() {
	c.Suspicious.Enable = false
	c.Suspicious.ThresholdQnameLen = 100
	c.Suspicious.ThresholdPacketLen = 1000
	c.Suspicious.ThresholdSlow = 1.0
	c.Suspicious.CommonQtypes = []string{"A", "AAAA", "TXT", "CNAME", "PTR",
		"NAPTR", "DNSKEY", "SRV", "SOA", "NS", "MX", "DS", "HTTPS"}
	c.Suspicious.UnallowedChars = []string{"\"", "==", "/", ":"}
	c.Suspicious.ThresholdMaxLabels = 10

	c.UserPrivacy.Enable = false
	c.UserPrivacy.AnonymizeIP = false
	c.UserPrivacy.MinimazeQname = false
	c.UserPrivacy.HashIP = false

	c.Normalize.Enable = false
	c.Normalize.QnameLowerCase = false
	c.Normalize.QuietText = false
	c.Normalize.AddTld = false
	c.Normalize.AddTldPlusOne = false

	c.Latency.Enable = false
	c.Latency.MeasureLatency = false
	c.Latency.UnansweredQueries = false
	c.Latency.QueriesTimeout = 2

	c.Reducer.Enable = false
	c.Reducer.RepetitiveTrafficDetector = false
	c.Reducer.WatchInterval = 5

	c.Filtering.Enable = false
	c.Filtering.DropFqdnFile = ""
	c.Filtering.DropDomainFile = ""
	c.Filtering.KeepFqdnFile = ""
	c.Filtering.KeepDomainFile = ""
	c.Filtering.DropQueryIpFile = ""
	c.Filtering.DropRcodes = []string{}
	c.Filtering.LogQueries = true
	c.Filtering.LogReplies = true
	c.Filtering.Downsample = 0

	c.GeoIP.Enable = false
	c.GeoIP.DbCountryFile = ""
	c.GeoIP.DbCityFile = ""
	c.GeoIP.DbAsnFile = ""

	c.Extract.Enable = false
	c.Extract.AddPayload = false
}

/* main configuration */
type Config struct {
	Global struct {
		TextFormat          string `yaml:"text-format"`
		TextFormatDelimiter string `yaml:"text-format-delimiter"`
		TextFormatBoundary  string `yaml:"text-format-boundary"`
		Trace               struct {
			Verbose      bool   `yaml:"verbose"`
			LogMalformed bool   `yaml:"log-malformed"`
			Filename     string `yaml:"filename"`
			MaxSize      int    `yaml:"max-size"`
			MaxBackups   int    `yaml:"max-backups"`
		} `yaml:"trace"`
		ServerIdentity string `yaml:"server-identity"`
	} `yaml:"global"`

	Collectors struct {
		Tail struct {
			Enable       bool   `yaml:"enable"`
			TimeLayout   string `yaml:"time-layout"`
			PatternQuery string `yaml:"pattern-query"`
			PatternReply string `yaml:"pattern-reply"`
			FilePath     string `yaml:"file-path"`
		} `yaml:"tail"`
		Dnstap struct {
			Enable        bool   `yaml:"enable"`
			ListenIP      string `yaml:"listen-ip"`
			ListenPort    int    `yaml:"listen-port"`
			SockPath      string `yaml:"sock-path"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsMinVersion string `yaml:"tls-min-version"`
			CertFile      string `yaml:"cert-file"`
			KeyFile       string `yaml:"key-file"`
			RcvBufSize    int    `yaml:"sock-rcvbuf"`
		} `yaml:"dnstap"`
		DnstapProxifier struct {
			Enable        bool   `yaml:"enable"`
			ListenIP      string `yaml:"listen-ip"`
			ListenPort    int    `yaml:"listen-port"`
			SockPath      string `yaml:"sock-path"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsMinVersion string `yaml:"tls-min-version"`
			CertFile      string `yaml:"cert-file"`
			KeyFile       string `yaml:"key-file"`
		} `yaml:"dnstap-proxifier"`
		AfpacketLiveCapture struct {
			Enable bool   `yaml:"enable"`
			Port   int    `yaml:"port"`
			Device string `yaml:"device"`
		} `yaml:"afpacket-sniffer"`
		XdpLiveCapture struct {
			Enable bool   `yaml:"enable"`
			Port   int    `yaml:"port"`
			Device string `yaml:"device"`
		} `yaml:"xdp-sniffer"`
		PowerDNS struct {
			Enable        bool   `yaml:"enable"`
			ListenIP      string `yaml:"listen-ip"`
			ListenPort    int    `yaml:"listen-port"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsMinVersion string `yaml:"tls-min-version"`
			CertFile      string `yaml:"cert-file"`
			KeyFile       string `yaml:"key-file"`
		} `yaml:"powerdns"`
		FileIngestor struct {
			Enable      bool   `yaml:"enable"`
			WatchDir    string `yaml:"watch-dir"`
			WatchMode   string `yaml:"watch-mode"`
			PcapDnsPort int    `yaml:"pcap-dns-port"`
			DeleteAfter bool   `yaml:"delete-after"`
		} `yaml:"file-ingestor"`
		Tzsp struct {
			Enable     bool   `yaml:"enable"`
			ListenIp   string `yaml:"listen-ip"`
			ListenPort int    `yaml:"listen-port"`
		}
	} `yaml:"collectors"`

	IngoingTransformers ConfigTransformers `yaml:"ingoing-transformers"`

	Loggers struct {
		Stdout struct {
			Enable     bool   `yaml:"enable"`
			Mode       string `yaml:"mode"`
			TextFormat string `yaml:"text-format"`
		} `yaml:"stdout"`
		Prometheus struct {
			Enable           bool   `yaml:"enable"`
			ListenIP         string `yaml:"listen-ip"`
			ListenPort       int    `yaml:"listen-port"`
			TlsSupport       bool   `yaml:"tls-support"`
			TlsMutual        bool   `yaml:"tls-mutual"`
			TlsMinVersion    string `yaml:"tls-min-version"`
			CertFile         string `yaml:"cert-file"`
			KeyFile          string `yaml:"key-file"`
			PromPrefix       string `yaml:"prometheus-prefix"`
			TopN             int    `yaml:"top-n"`
			BasicAuthLogin   string `yaml:"basic-auth-login"`
			BasicAuthPwd     string `yaml:"basic-auth-pwd"`
			BasicAuthEnabled bool   `yaml:"basic-auth-enable"`
		} `yaml:"prometheus"`
		RestAPI struct {
			Enable         bool   `yaml:"enable"`
			ListenIP       string `yaml:"listen-ip"`
			ListenPort     int    `yaml:"listen-port"`
			BasicAuthLogin string `yaml:"basic-auth-login"`
			BasicAuthPwd   string `yaml:"basic-auth-pwd"`
			TlsSupport     bool   `yaml:"tls-support"`
			TlsMinVersion  string `yaml:"tls-min-version"`
			CertFile       string `yaml:"cert-file"`
			KeyFile        string `yaml:"key-file"`
			TopN           int    `yaml:"top-n"`
		} `yaml:"restapi"`
		LogFile struct {
			Enable              bool   `yaml:"enable"`
			FilePath            string `yaml:"file-path"`
			MaxSize             int    `yaml:"max-size"`
			MaxFiles            int    `yaml:"max-files"`
			FlushInterval       int    `yaml:"flush-interval"`
			Compress            bool   `yaml:"compress"`
			CompressInterval    int    `yaml:"compress-interval"`
			CompressPostCommand string `yaml:"compress-postcommand"`
			Mode                string `yaml:"mode"`
			PostRotateCommand   string `yaml:"postrotate-command"`
			PostRotateDelete    bool   `yaml:"postrotate-delete-success"`
			TextFormat          string `yaml:"text-format"`
		} `yaml:"logfile"`
		Dnstap struct {
			Enable            bool   `yaml:"enable"`
			RemoteAddress     string `yaml:"remote-address"`
			RemotePort        int    `yaml:"remote-port"`
			SockPath          string `yaml:"sock-path"`
			ConnectTimeout    int    `yaml:"connect-timeout"`
			RetryInterval     int    `yaml:"retry-interval"`
			FlushInterval     int    `yaml:"flush-interval"`
			TlsSupport        bool   `yaml:"tls-support"`
			TlsInsecure       bool   `yaml:"tls-insecure"`
			TlsMinVersion     string `yaml:"tls-min-version"`
			ServerId          string `yaml:"server-id"`
			OverwriteIdentity bool   `yaml:"overwrite-identity"`
			BufferSize        int    `yaml:"buffer-size"`
		} `yaml:"dnstap"`
		TcpClient struct {
			Enable           bool   `yaml:"enable"`
			RemoteAddress    string `yaml:"remote-address"`
			RemotePort       int    `yaml:"remote-port"`
			SockPath         string `yaml:"sock-path"`
			RetryInterval    int    `yaml:"retry-interval"`
			Transport        string `yaml:"transport"`
			TlsSupport       bool   `yaml:"tls-support"`
			TlsInsecure      bool   `yaml:"tls-insecure"`
			TlsMinVersion    string `yaml:"tls-min-version"`
			Mode             string `yaml:"mode"`
			TextFormat       string `yaml:"text-format"`
			PayloadDelimiter string `yaml:"delimiter"`
			BufferSize       int    `yaml:"buffer-size"`
			FlushInterval    int    `yaml:"flush-interval"`
			ConnectTimeout   int    `yaml:"connect-timeout"`
		} `yaml:"tcpclient"`
		Syslog struct {
			Enable        bool   `yaml:"enable"`
			Severity      string `yaml:"severity"`
			Facility      string `yaml:"facility"`
			Transport     string `yaml:"transport"`
			RemoteAddress string `yaml:"remote-address"`
			TextFormat    string `yaml:"text-format"`
			Mode          string `yaml:"mode"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
			Format        string `yaml:"format"`
		} `yaml:"syslog"`
		Fluentd struct {
			Enable         bool   `yaml:"enable"`
			RemoteAddress  string `yaml:"remote-address"`
			RemotePort     int    `yaml:"remote-port"`
			SockPath       string `yaml:"sock-path"`
			ConnectTimeout int    `yaml:"connect-timeout"`
			RetryInterval  int    `yaml:"retry-interval"`
			FlushInterval  int    `yaml:"flush-interval"`
			Transport      string `yaml:"transport"`
			TlsSupport     bool   `yaml:"tls-support"`
			TlsInsecure    bool   `yaml:"tls-insecure"`
			TlsMinVersion  string `yaml:"tls-min-version"`
			Tag            string `yaml:"tag"`
			BufferSize     int    `yaml:"buffer-size"`
		} `yaml:"fluentd"`
		InfluxDB struct {
			Enable        bool   `yaml:"enable"`
			ServerURL     string `yaml:"server-url"`
			AuthToken     string `yaml:"auth-token"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
			Bucket        string `yaml:"bucket"`
			Organization  string `yaml:"organization"`
		} `yaml:"influxdb"`
		LokiClient struct {
			Enable         bool   `yaml:"enable"`
			ServerURL      string `yaml:"server-url"`
			JobName        string `yaml:"job-name"`
			Mode           string `yaml:"mode"`
			FlushInterval  int    `yaml:"flush-interval"`
			BatchSize      int    `yaml:"batch-size"`
			RetryInterval  int    `yaml:"retry-interval"`
			TextFormat     string `yaml:"text-format"`
			ProxyURL       string `yaml:"proxy-url"`
			TlsInsecure    bool   `yaml:"tls-insecure"`
			TlsMinVersion  string `yaml:"tls-min-version"`
			BasicAuthLogin string `yaml:"basic-auth-login"`
			BasicAuthPwd   string `yaml:"basic-auth-pwd"`
			TenantId       string `yaml:"tenant-id"`
		} `yaml:"lokiclient"`
		Statsd struct {
			Enable        bool   `yaml:"enable"`
			Prefix        string `yaml:"prefix"`
			RemoteAddress string `yaml:"remote-address"`
			RemotePort    int    `yaml:"remote-port"`
			Transport     string `yaml:"transport"`
			FlushInterval int    `yaml:"flush-interval"`
			TlsSupport    bool   `yaml:"tls-support"`
			TlsInsecure   bool   `yaml:"tls-insecure"`
			TlsMinVersion string `yaml:"tls-min-version"`
		} `yaml:"statsd"`
		ElasticSearchClient struct {
			Enable bool   `yaml:"enable"`
			URL    string `yaml:"url"`
		} `yaml:"elasticsearch"`
		ScalyrClient struct {
			Enable        bool                   `yaml:"enable"`
			Mode          string                 `yaml:"mode"`
			TextFormat    string                 `yaml:"text-format"`
			SessionInfo   map[string]string      `yaml:"sessioninfo"`
			Attrs         map[string]interface{} `yaml:"attrs"`
			ServerURL     string                 `yaml:"server-url"`
			ApiKey        string                 `yaml:"apikey"`
			Parser        string                 `yaml:"parser"`
			FlushInterval int                    `yaml:"flush-interval"`
			ProxyURL      string                 `yaml:"proxy-url"`
			TlsInsecure   bool                   `yaml:"tls-insecure"`
			TlsMinVersion string                 `yaml:"tls-min-version"`
		} `yaml:"scalyrclient"`
		RedisPub struct {
			Enable           bool   `yaml:"enable"`
			RemoteAddress    string `yaml:"remote-address"`
			RemotePort       int    `yaml:"remote-port"`
			SockPath         string `yaml:"sock-path"`
			RetryInterval    int    `yaml:"retry-interval"`
			Transport        string `yaml:"transport"`
			TlsSupport       bool   `yaml:"tls-support"`
			TlsInsecure      bool   `yaml:"tls-insecure"`
			TlsMinVersion    string `yaml:"tls-min-version"`
			Mode             string `yaml:"mode"`
			TextFormat       string `yaml:"text-format"`
			PayloadDelimiter string `yaml:"delimiter"`
			BufferSize       int    `yaml:"buffer-size"`
			FlushInterval    int    `yaml:"flush-interval"`
			ConnectTimeout   int    `yaml:"connect-timeout"`
			RedisChannel     string `yaml:"redis-channel"`
		} `yaml:"redispub"`
	} `yaml:"loggers"`

	OutgoingTransformers ConfigTransformers `yaml:"outgoing-transformers"`

	Multiplexer struct {
		Collectors []MultiplexInOut  `yaml:"collectors"`
		Loggers    []MultiplexInOut  `yaml:"loggers"`
		Routes     []MultiplexRoutes `yaml:"routes"`
	} `yaml:"multiplexer"`
}

func (c *Config) SetDefault() {
	// global config
	c.Global.TextFormat = "timestamp identity operation rcode queryip queryport family protocol length qname qtype latency"
	c.Global.TextFormatDelimiter = " "
	c.Global.TextFormatBoundary = "\""

	c.Global.Trace.Verbose = false
	c.Global.Trace.LogMalformed = false
	c.Global.Trace.Filename = ""
	c.Global.Trace.MaxSize = 10
	c.Global.Trace.MaxBackups = 10
	c.Global.ServerIdentity = ""

	// multiplexer
	c.Multiplexer.Collectors = []MultiplexInOut{}
	c.Multiplexer.Loggers = []MultiplexInOut{}
	c.Multiplexer.Routes = []MultiplexRoutes{}

	// Collectors
	c.Collectors.Tail.Enable = false
	c.Collectors.Tail.TimeLayout = ""
	c.Collectors.Tail.PatternQuery = ""
	c.Collectors.Tail.PatternReply = ""
	c.Collectors.Tail.FilePath = ""

	c.Collectors.Dnstap.Enable = false
	c.Collectors.Dnstap.ListenIP = ANY_IP
	c.Collectors.Dnstap.ListenPort = 6000
	c.Collectors.Dnstap.SockPath = ""
	c.Collectors.Dnstap.TlsSupport = false
	c.Collectors.Dnstap.TlsMinVersion = TLS_v12
	c.Collectors.Dnstap.CertFile = ""
	c.Collectors.Dnstap.KeyFile = ""
	c.Collectors.Dnstap.RcvBufSize = 0

	c.Collectors.DnstapProxifier.Enable = false
	c.Collectors.DnstapProxifier.ListenIP = ANY_IP
	c.Collectors.DnstapProxifier.ListenPort = 6000
	c.Collectors.DnstapProxifier.SockPath = ""
	c.Collectors.DnstapProxifier.TlsSupport = false
	c.Collectors.DnstapProxifier.TlsMinVersion = TLS_v12
	c.Collectors.DnstapProxifier.CertFile = ""
	c.Collectors.DnstapProxifier.KeyFile = ""

	c.Collectors.XdpLiveCapture.Enable = false
	c.Collectors.XdpLiveCapture.Device = ""

	c.Collectors.AfpacketLiveCapture.Enable = false
	c.Collectors.AfpacketLiveCapture.Port = 53
	c.Collectors.AfpacketLiveCapture.Device = ""

	c.Collectors.PowerDNS.Enable = false
	c.Collectors.PowerDNS.ListenIP = ANY_IP
	c.Collectors.PowerDNS.ListenPort = 6001
	c.Collectors.PowerDNS.TlsSupport = false
	c.Collectors.PowerDNS.TlsMinVersion = TLS_v12
	c.Collectors.PowerDNS.CertFile = ""
	c.Collectors.PowerDNS.KeyFile = ""

	c.Collectors.FileIngestor.Enable = false
	c.Collectors.FileIngestor.WatchDir = ""
	c.Collectors.FileIngestor.PcapDnsPort = 53
	c.Collectors.FileIngestor.WatchMode = MODE_PCAP
	c.Collectors.FileIngestor.DeleteAfter = false

	c.Collectors.Tzsp.Enable = false
	c.Collectors.Tzsp.ListenIp = ANY_IP
	c.Collectors.Tzsp.ListenPort = 10000

	// Transformers for collectors
	c.IngoingTransformers.SetDefault()

	// Loggers
	c.Loggers.Stdout.Enable = false
	c.Loggers.Stdout.Mode = MODE_TEXT
	c.Loggers.Stdout.TextFormat = ""

	c.Loggers.Dnstap.Enable = false
	c.Loggers.Dnstap.RemoteAddress = LOCALHOST_IP
	c.Loggers.Dnstap.RemotePort = 6000
	c.Loggers.Dnstap.ConnectTimeout = 5
	c.Loggers.Dnstap.RetryInterval = 10
	c.Loggers.Dnstap.FlushInterval = 30
	c.Loggers.Dnstap.SockPath = ""
	c.Loggers.Dnstap.TlsSupport = false
	c.Loggers.Dnstap.TlsInsecure = false
	c.Loggers.Dnstap.TlsMinVersion = TLS_v12
	c.Loggers.Dnstap.ServerId = ""
	c.Loggers.Dnstap.OverwriteIdentity = false
	c.Loggers.Dnstap.BufferSize = 100

	c.Loggers.LogFile.Enable = false
	c.Loggers.LogFile.FilePath = ""
	c.Loggers.LogFile.FlushInterval = 10
	c.Loggers.LogFile.MaxSize = 100
	c.Loggers.LogFile.MaxFiles = 10
	c.Loggers.LogFile.Compress = false
	c.Loggers.LogFile.CompressInterval = 60
	c.Loggers.LogFile.CompressPostCommand = ""
	c.Loggers.LogFile.Mode = MODE_TEXT
	c.Loggers.LogFile.PostRotateCommand = ""
	c.Loggers.LogFile.PostRotateDelete = false
	c.Loggers.LogFile.TextFormat = ""

	c.Loggers.Prometheus.Enable = false
	c.Loggers.Prometheus.ListenIP = LOCALHOST_IP
	c.Loggers.Prometheus.ListenPort = 8081
	c.Loggers.Prometheus.TlsSupport = false
	c.Loggers.Prometheus.TlsMutual = false
	c.Loggers.Prometheus.TlsMinVersion = TLS_v12
	c.Loggers.Prometheus.CertFile = ""
	c.Loggers.Prometheus.KeyFile = ""
	c.Loggers.Prometheus.PromPrefix = PROG_NAME
	c.Loggers.Prometheus.TopN = 10
	c.Loggers.Prometheus.BasicAuthLogin = "admin"
	c.Loggers.Prometheus.BasicAuthPwd = "changeme"
	c.Loggers.Prometheus.BasicAuthEnabled = true

	c.Loggers.RestAPI.Enable = false
	c.Loggers.RestAPI.ListenIP = LOCALHOST_IP
	c.Loggers.RestAPI.ListenPort = 8080
	c.Loggers.RestAPI.BasicAuthLogin = "admin"
	c.Loggers.RestAPI.BasicAuthPwd = "changeme"
	c.Loggers.RestAPI.TlsSupport = false
	c.Loggers.RestAPI.TlsMinVersion = TLS_v12
	c.Loggers.RestAPI.CertFile = ""
	c.Loggers.RestAPI.KeyFile = ""
	c.Loggers.RestAPI.TopN = 100

	c.Loggers.TcpClient.Enable = false
	c.Loggers.TcpClient.RemoteAddress = LOCALHOST_IP
	c.Loggers.TcpClient.RemotePort = 9999
	c.Loggers.TcpClient.SockPath = ""
	c.Loggers.TcpClient.RetryInterval = 10
	c.Loggers.TcpClient.Transport = "tcp"
	c.Loggers.TcpClient.TlsSupport = false
	c.Loggers.TcpClient.TlsInsecure = false
	c.Loggers.TcpClient.TlsMinVersion = TLS_v12
	c.Loggers.TcpClient.Mode = MODE_JSON
	c.Loggers.TcpClient.TextFormat = ""
	c.Loggers.TcpClient.PayloadDelimiter = "\n"
	c.Loggers.TcpClient.BufferSize = 100
	c.Loggers.TcpClient.ConnectTimeout = 5
	c.Loggers.TcpClient.FlushInterval = 30

	c.Loggers.Syslog.Enable = false
	c.Loggers.Syslog.Severity = "INFO"
	c.Loggers.Syslog.Facility = "DAEMON"
	c.Loggers.Syslog.Transport = "local"
	c.Loggers.Syslog.RemoteAddress = "127.0.0.1:514"
	c.Loggers.Syslog.TextFormat = ""
	c.Loggers.Syslog.Mode = MODE_TEXT
	c.Loggers.Syslog.TlsSupport = false
	c.Loggers.Syslog.TlsInsecure = false
	c.Loggers.Syslog.TlsMinVersion = TLS_v12

	c.Loggers.Fluentd.Enable = false
	c.Loggers.Fluentd.RemoteAddress = LOCALHOST_IP
	c.Loggers.Fluentd.RemotePort = 24224
	c.Loggers.Fluentd.SockPath = ""
	c.Loggers.Fluentd.RetryInterval = 10
	c.Loggers.Fluentd.ConnectTimeout = 5
	c.Loggers.Fluentd.FlushInterval = 30
	c.Loggers.Fluentd.Transport = "tcp"
	c.Loggers.Fluentd.TlsSupport = false
	c.Loggers.Fluentd.TlsInsecure = false
	c.Loggers.Fluentd.TlsMinVersion = TLS_v12
	c.Loggers.Fluentd.Tag = "dns.collector"
	c.Loggers.Fluentd.BufferSize = 100

	c.Loggers.InfluxDB.Enable = false
	c.Loggers.InfluxDB.ServerURL = "http://localhost:8086"
	c.Loggers.InfluxDB.AuthToken = ""
	c.Loggers.InfluxDB.TlsSupport = false
	c.Loggers.InfluxDB.TlsInsecure = false
	c.Loggers.InfluxDB.TlsMinVersion = TLS_v12
	c.Loggers.InfluxDB.Bucket = ""
	c.Loggers.InfluxDB.Organization = ""

	c.Loggers.LokiClient.Enable = false
	c.Loggers.LokiClient.ServerURL = "http://localhost:3100/loki/api/v1/push"
	c.Loggers.LokiClient.JobName = PROG_NAME
	c.Loggers.LokiClient.Mode = MODE_TEXT
	c.Loggers.LokiClient.FlushInterval = 5
	c.Loggers.LokiClient.BatchSize = 1024 * 1024
	c.Loggers.LokiClient.RetryInterval = 10
	c.Loggers.LokiClient.TextFormat = ""
	c.Loggers.LokiClient.ProxyURL = ""
	c.Loggers.LokiClient.TlsInsecure = false
	c.Loggers.LokiClient.TlsMinVersion = TLS_v12
	c.Loggers.LokiClient.BasicAuthLogin = ""
	c.Loggers.LokiClient.BasicAuthPwd = ""
	c.Loggers.LokiClient.TenantId = ""

	c.Loggers.Statsd.Enable = false
	c.Loggers.Statsd.Prefix = PROG_NAME
	c.Loggers.Statsd.RemoteAddress = LOCALHOST_IP
	c.Loggers.Statsd.RemotePort = 8125
	c.Loggers.Statsd.Transport = "udp"
	c.Loggers.Statsd.FlushInterval = 10
	c.Loggers.Statsd.TlsSupport = false
	c.Loggers.Statsd.TlsInsecure = false
	c.Loggers.Statsd.TlsMinVersion = TLS_v12

	c.Loggers.ElasticSearchClient.Enable = false
	c.Loggers.ElasticSearchClient.URL = "http://127.0.0.1:9200/indexname/_doc"

	c.Loggers.RedisPub.Enable = false
	c.Loggers.RedisPub.RemoteAddress = LOCALHOST_IP
	c.Loggers.RedisPub.RemotePort = 6379
	c.Loggers.RedisPub.SockPath = ""
	c.Loggers.RedisPub.RetryInterval = 10
	c.Loggers.RedisPub.Transport = SOCKET_TCP
	c.Loggers.RedisPub.TlsSupport = false
	c.Loggers.RedisPub.TlsInsecure = false
	c.Loggers.RedisPub.TlsMinVersion = TLS_v12
	c.Loggers.RedisPub.Mode = MODE_JSON
	c.Loggers.RedisPub.TextFormat = ""
	c.Loggers.RedisPub.PayloadDelimiter = "\n"
	c.Loggers.RedisPub.BufferSize = 100
	c.Loggers.RedisPub.ConnectTimeout = 5
	c.Loggers.RedisPub.FlushInterval = 30
	c.Loggers.RedisPub.RedisChannel = "dns_collector"

	// Transformers for loggers
	c.OutgoingTransformers.SetDefault()

}

func (c *Config) GetServerIdentity() string {
	if len(c.Global.ServerIdentity) > 0 {
		return c.Global.ServerIdentity
	} else {
		hostname, err := os.Hostname()
		if err == nil {
			return hostname
		} else {
			return "undefined"
		}
	}
}

func ReloadConfig(configPath string, config *Config) error {
	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return err
	}
	return nil
}

func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}
	config.SetDefault()

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func GetFakeConfig() *Config {
	config := &Config{}
	config.SetDefault()
	return config
}

func GetFakeConfigTransformers() *ConfigTransformers {
	config := &ConfigTransformers{}
	config.SetDefault()
	return config
}
