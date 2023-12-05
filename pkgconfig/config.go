package pkgconfig

import (
	"os"

	"github.com/dmachard/go-dnscollector/netlib"
	"gopkg.in/yaml.v3"
)

func IsValidMode(mode string) bool {
	switch mode {
	case
		ModeText,
		ModeJSON,
		ModeFlatJSON:
		return true
	}
	return false
}

type Config struct {
	Global               ConfigGlobal       `yaml:"global"`
	Collectors           ConfigCollectors   `yaml:"collectors"`
	IngoingTransformers  ConfigTransformers `yaml:"collectors-transformers"`
	Loggers              ConfigLoggers      `yaml:"loggers"`
	OutgoingTransformers ConfigTransformers `yaml:"loggers-transformers"`
	Multiplexer          ConfigMultiplexer  `yaml:"multiplexer"`
}

func (c *Config) SetDefault() {
	// global config
	c.Global.TextFormat = "timestamp identity operation rcode queryip queryport family protocol length-unit qname qtype latency"
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
	c.Collectors.Dnstap.ListenIP = AnyIP
	c.Collectors.Dnstap.ListenPort = 6000
	c.Collectors.Dnstap.SockPath = ""
	c.Collectors.Dnstap.TLSSupport = false
	c.Collectors.Dnstap.TLSMinVersion = TLSV12
	c.Collectors.Dnstap.CertFile = ""
	c.Collectors.Dnstap.KeyFile = ""
	c.Collectors.Dnstap.RcvBufSize = 0
	c.Collectors.Dnstap.ResetConn = true
	c.Collectors.Dnstap.ChannelBufferSize = 65535
	c.Collectors.Dnstap.DisableDNSParser = false

	c.Collectors.DnstapProxifier.Enable = false
	c.Collectors.DnstapProxifier.ListenIP = AnyIP
	c.Collectors.DnstapProxifier.ListenPort = 6000
	c.Collectors.DnstapProxifier.SockPath = ""
	c.Collectors.DnstapProxifier.TLSSupport = false
	c.Collectors.DnstapProxifier.TLSMinVersion = TLSV12
	c.Collectors.DnstapProxifier.CertFile = ""
	c.Collectors.DnstapProxifier.KeyFile = ""

	c.Collectors.XdpLiveCapture.Enable = false
	c.Collectors.XdpLiveCapture.Device = ""
	c.Collectors.XdpLiveCapture.ChannelBufferSize = 65535

	c.Collectors.AfpacketLiveCapture.Enable = false
	c.Collectors.AfpacketLiveCapture.Port = 53
	c.Collectors.AfpacketLiveCapture.Device = ""
	c.Collectors.AfpacketLiveCapture.ChannelBufferSize = 65535

	c.Collectors.PowerDNS.Enable = false
	c.Collectors.PowerDNS.ListenIP = AnyIP
	c.Collectors.PowerDNS.ListenPort = 6001
	c.Collectors.PowerDNS.TLSSupport = false
	c.Collectors.PowerDNS.TLSMinVersion = TLSV12
	c.Collectors.PowerDNS.CertFile = ""
	c.Collectors.PowerDNS.KeyFile = ""
	c.Collectors.PowerDNS.AddDNSPayload = false
	c.Collectors.PowerDNS.RcvBufSize = 0
	c.Collectors.PowerDNS.ResetConn = true
	c.Collectors.PowerDNS.ChannelBufferSize = 65535

	c.Collectors.FileIngestor.Enable = false
	c.Collectors.FileIngestor.WatchDir = ""
	c.Collectors.FileIngestor.PcapDNSPort = 53
	c.Collectors.FileIngestor.WatchMode = ModePCAP
	c.Collectors.FileIngestor.DeleteAfter = false
	c.Collectors.FileIngestor.ChannelBufferSize = 65535

	c.Collectors.Tzsp.Enable = false
	c.Collectors.Tzsp.ListenIP = AnyIP
	c.Collectors.Tzsp.ListenPort = 10000
	c.Collectors.Tzsp.ChannelBufferSize = 65535

	// Transformers for collectors
	c.IngoingTransformers.SetDefault()

	// Loggers
	c.Loggers.Stdout.Enable = false
	c.Loggers.Stdout.Mode = ModeText
	c.Loggers.Stdout.TextFormat = ""
	c.Loggers.Stdout.ChannelBufferSize = 65535

	c.Loggers.DNSTap.Enable = false
	c.Loggers.DNSTap.RemoteAddress = LocalhostIP
	c.Loggers.DNSTap.RemotePort = 6000
	c.Loggers.DNSTap.Transport = netlib.SocketTCP
	c.Loggers.DNSTap.ConnectTimeout = 5
	c.Loggers.DNSTap.RetryInterval = 10
	c.Loggers.DNSTap.FlushInterval = 30
	c.Loggers.DNSTap.SockPath = ""
	c.Loggers.DNSTap.TLSSupport = false
	c.Loggers.DNSTap.TLSInsecure = false
	c.Loggers.DNSTap.TLSMinVersion = TLSV12
	c.Loggers.DNSTap.CAFile = ""
	c.Loggers.DNSTap.CertFile = ""
	c.Loggers.DNSTap.KeyFile = ""
	c.Loggers.DNSTap.ServerID = ""
	c.Loggers.DNSTap.OverwriteIdentity = false
	c.Loggers.DNSTap.BufferSize = 100
	c.Loggers.DNSTap.ChannelBufferSize = 65535

	c.Loggers.LogFile.Enable = false
	c.Loggers.LogFile.FilePath = ""
	c.Loggers.LogFile.FlushInterval = 10
	c.Loggers.LogFile.MaxSize = 100
	c.Loggers.LogFile.MaxFiles = 10
	c.Loggers.LogFile.Compress = false
	c.Loggers.LogFile.CompressInterval = 60
	c.Loggers.LogFile.CompressPostCommand = ""
	c.Loggers.LogFile.Mode = ModeText
	c.Loggers.LogFile.PostRotateCommand = ""
	c.Loggers.LogFile.PostRotateDelete = false
	c.Loggers.LogFile.TextFormat = ""
	c.Loggers.LogFile.ChannelBufferSize = 65535

	c.Loggers.Prometheus.Enable = false
	c.Loggers.Prometheus.ListenIP = LocalhostIP
	c.Loggers.Prometheus.ListenPort = 8081
	c.Loggers.Prometheus.TLSSupport = false
	c.Loggers.Prometheus.TLSMutual = false
	c.Loggers.Prometheus.TLSMinVersion = TLSV12
	c.Loggers.Prometheus.CertFile = ""
	c.Loggers.Prometheus.KeyFile = ""
	c.Loggers.Prometheus.PromPrefix = ProgName
	c.Loggers.Prometheus.TopN = 10
	c.Loggers.Prometheus.BasicAuthLogin = "admin"
	c.Loggers.Prometheus.BasicAuthPwd = "changeme"
	c.Loggers.Prometheus.BasicAuthEnabled = true
	c.Loggers.Prometheus.ChannelBufferSize = 65535
	c.Loggers.Prometheus.HistogramMetricsEnabled = false

	c.Loggers.RestAPI.Enable = false
	c.Loggers.RestAPI.ListenIP = LocalhostIP
	c.Loggers.RestAPI.ListenPort = 8080
	c.Loggers.RestAPI.BasicAuthLogin = "admin"
	c.Loggers.RestAPI.BasicAuthPwd = "changeme"
	c.Loggers.RestAPI.TLSSupport = false
	c.Loggers.RestAPI.TLSMinVersion = TLSV12
	c.Loggers.RestAPI.CertFile = ""
	c.Loggers.RestAPI.KeyFile = ""
	c.Loggers.RestAPI.TopN = 100
	c.Loggers.RestAPI.ChannelBufferSize = 65535

	c.Loggers.TCPClient.Enable = false
	c.Loggers.TCPClient.RemoteAddress = LocalhostIP
	c.Loggers.TCPClient.RemotePort = 9999
	c.Loggers.TCPClient.SockPath = ""
	c.Loggers.TCPClient.RetryInterval = 10
	c.Loggers.TCPClient.Transport = netlib.SocketTCP
	c.Loggers.TCPClient.TLSSupport = false
	c.Loggers.TCPClient.TLSInsecure = false
	c.Loggers.TCPClient.TLSMinVersion = TLSV12
	c.Loggers.TCPClient.CAFile = ""
	c.Loggers.TCPClient.CertFile = ""
	c.Loggers.TCPClient.KeyFile = ""
	c.Loggers.TCPClient.Mode = ModeFlatJSON
	c.Loggers.TCPClient.TextFormat = ""
	c.Loggers.TCPClient.PayloadDelimiter = "\n"
	c.Loggers.TCPClient.BufferSize = 100
	c.Loggers.TCPClient.ConnectTimeout = 5
	c.Loggers.TCPClient.FlushInterval = 30
	c.Loggers.TCPClient.ChannelBufferSize = 65535

	c.Loggers.Syslog.Enable = false
	c.Loggers.Syslog.Severity = "INFO"
	c.Loggers.Syslog.Facility = "DAEMON"
	c.Loggers.Syslog.Transport = "local"
	c.Loggers.Syslog.RemoteAddress = "127.0.0.1:514"
	c.Loggers.Syslog.TextFormat = ""
	c.Loggers.Syslog.Mode = ModeText
	c.Loggers.Syslog.RetryInterval = 10
	c.Loggers.Syslog.TLSInsecure = false
	c.Loggers.Syslog.TLSMinVersion = TLSV12
	c.Loggers.Syslog.CAFile = ""
	c.Loggers.Syslog.CertFile = ""
	c.Loggers.Syslog.KeyFile = ""
	c.Loggers.Syslog.ChannelBufferSize = 65535
	c.Loggers.Syslog.Tag = ""
	c.Loggers.Syslog.Framer = ""
	c.Loggers.Syslog.Formatter = "rfc5424"
	c.Loggers.Syslog.Hostname = ""
	c.Loggers.Syslog.AppName = "DNScollector"
	c.Loggers.Syslog.ReplaceNullChar = "|"
	c.Loggers.Syslog.FlushInterval = 30
	c.Loggers.Syslog.BufferSize = 100

	c.Loggers.Fluentd.Enable = false
	c.Loggers.Fluentd.RemoteAddress = LocalhostIP
	c.Loggers.Fluentd.RemotePort = 24224
	c.Loggers.Fluentd.SockPath = "" // deprecated
	c.Loggers.Fluentd.RetryInterval = 10
	c.Loggers.Fluentd.ConnectTimeout = 5
	c.Loggers.Fluentd.FlushInterval = 30
	c.Loggers.Fluentd.Transport = netlib.SocketTCP
	c.Loggers.Fluentd.TLSSupport = false // deprecated
	c.Loggers.Fluentd.TLSInsecure = false
	c.Loggers.Fluentd.TLSMinVersion = TLSV12
	c.Loggers.Fluentd.CAFile = ""
	c.Loggers.Fluentd.CertFile = ""
	c.Loggers.Fluentd.KeyFile = ""
	c.Loggers.Fluentd.Tag = "dns.collector"
	c.Loggers.Fluentd.BufferSize = 100
	c.Loggers.Fluentd.ChannelBufferSize = 65535

	c.Loggers.InfluxDB.Enable = false
	c.Loggers.InfluxDB.ServerURL = "http://localhost:8086"
	c.Loggers.InfluxDB.AuthToken = ""
	c.Loggers.InfluxDB.TLSSupport = false
	c.Loggers.InfluxDB.TLSInsecure = false
	c.Loggers.InfluxDB.TLSMinVersion = TLSV12
	c.Loggers.InfluxDB.CAFile = ""
	c.Loggers.InfluxDB.CertFile = ""
	c.Loggers.InfluxDB.KeyFile = ""
	c.Loggers.InfluxDB.Bucket = ""
	c.Loggers.InfluxDB.Organization = ""
	c.Loggers.InfluxDB.ChannelBufferSize = 65535

	c.Loggers.LokiClient.Enable = false
	c.Loggers.LokiClient.ServerURL = "http://localhost:3100/loki/api/v1/push"
	c.Loggers.LokiClient.JobName = ProgName
	c.Loggers.LokiClient.Mode = ModeText
	c.Loggers.LokiClient.FlushInterval = 5
	c.Loggers.LokiClient.BatchSize = 1024 * 1024
	c.Loggers.LokiClient.RetryInterval = 10
	c.Loggers.LokiClient.TextFormat = ""
	c.Loggers.LokiClient.ProxyURL = ""
	c.Loggers.LokiClient.TLSInsecure = false
	c.Loggers.LokiClient.TLSMinVersion = TLSV12
	c.Loggers.LokiClient.CAFile = ""
	c.Loggers.LokiClient.CertFile = ""
	c.Loggers.LokiClient.KeyFile = ""
	c.Loggers.LokiClient.BasicAuthLogin = ""
	c.Loggers.LokiClient.BasicAuthPwd = ""
	c.Loggers.LokiClient.BasicAuthPwdFile = ""
	c.Loggers.LokiClient.TenantID = ""
	c.Loggers.LokiClient.ChannelBufferSize = 65535

	c.Loggers.Statsd.Enable = false
	c.Loggers.Statsd.Prefix = ProgName
	c.Loggers.Statsd.RemoteAddress = LocalhostIP
	c.Loggers.Statsd.RemotePort = 8125
	c.Loggers.Statsd.Transport = netlib.SocketUDP
	c.Loggers.Statsd.ConnectTimeout = 5
	c.Loggers.Statsd.FlushInterval = 10
	c.Loggers.Statsd.TLSSupport = false // deprecated
	c.Loggers.Statsd.TLSInsecure = false
	c.Loggers.Statsd.TLSMinVersion = TLSV12
	c.Loggers.Statsd.CAFile = ""
	c.Loggers.Statsd.CertFile = ""
	c.Loggers.Statsd.KeyFile = ""
	c.Loggers.Statsd.ChannelBufferSize = 65535

	c.Loggers.ElasticSearchClient.Enable = false
	c.Loggers.ElasticSearchClient.Server = "http://127.0.0.1:9200/"
	c.Loggers.ElasticSearchClient.Index = ""
	c.Loggers.ElasticSearchClient.ChannelBufferSize = 65535
	c.Loggers.ElasticSearchClient.BulkSize = 100
	c.Loggers.ElasticSearchClient.FlushInterval = 10

	c.Loggers.RedisPub.Enable = false
	c.Loggers.RedisPub.RemoteAddress = LocalhostIP
	c.Loggers.RedisPub.RemotePort = 6379
	c.Loggers.RedisPub.SockPath = ""
	c.Loggers.RedisPub.RetryInterval = 10
	c.Loggers.RedisPub.Transport = netlib.SocketTCP
	c.Loggers.RedisPub.TLSSupport = false
	c.Loggers.RedisPub.TLSInsecure = false
	c.Loggers.RedisPub.TLSMinVersion = TLSV12
	c.Loggers.RedisPub.CAFile = ""
	c.Loggers.RedisPub.CertFile = ""
	c.Loggers.RedisPub.KeyFile = ""
	c.Loggers.RedisPub.Mode = ModeFlatJSON
	c.Loggers.RedisPub.TextFormat = ""
	c.Loggers.RedisPub.PayloadDelimiter = "\n"
	c.Loggers.RedisPub.BufferSize = 100
	c.Loggers.RedisPub.ConnectTimeout = 5
	c.Loggers.RedisPub.FlushInterval = 30
	c.Loggers.RedisPub.RedisChannel = "dns_collector"
	c.Loggers.RedisPub.ChannelBufferSize = 65535

	c.Loggers.KafkaProducer.Enable = false
	c.Loggers.KafkaProducer.RemoteAddress = LocalhostIP
	c.Loggers.KafkaProducer.RemotePort = 9092
	c.Loggers.KafkaProducer.RetryInterval = 10
	c.Loggers.KafkaProducer.TLSSupport = false
	c.Loggers.KafkaProducer.TLSInsecure = false
	c.Loggers.KafkaProducer.TLSMinVersion = TLSV12
	c.Loggers.KafkaProducer.CAFile = ""
	c.Loggers.KafkaProducer.CertFile = ""
	c.Loggers.KafkaProducer.KeyFile = ""
	c.Loggers.KafkaProducer.SaslSupport = false
	c.Loggers.KafkaProducer.SaslUsername = ""
	c.Loggers.KafkaProducer.SaslPassword = ""
	c.Loggers.KafkaProducer.SaslMechanism = SASLMechanismPlain
	c.Loggers.KafkaProducer.Mode = ModeFlatJSON
	c.Loggers.KafkaProducer.BufferSize = 100
	c.Loggers.KafkaProducer.ConnectTimeout = 5
	c.Loggers.KafkaProducer.FlushInterval = 10
	c.Loggers.KafkaProducer.Topic = "dnscollector"
	c.Loggers.KafkaProducer.Partition = 0
	c.Loggers.KafkaProducer.ChannelBufferSize = 65535
	c.Loggers.KafkaProducer.Compression = CompressNone

	c.Loggers.FalcoClient.Enable = false
	c.Loggers.FalcoClient.URL = "http://127.0.0.1:9200"
	c.Loggers.FalcoClient.ChannelBufferSize = 65535

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
