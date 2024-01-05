package pkgconfig

import (
	"reflect"

	"github.com/dmachard/go-dnscollector/netlib"
	"github.com/prometheus/prometheus/model/relabel"
)

type ConfigLoggers struct {
	Stdout struct {
		Enable            bool   `yaml:"enable"`
		Mode              string `yaml:"mode"`
		TextFormat        string `yaml:"text-format"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"stdout"`
	Prometheus struct {
		Enable                    bool     `yaml:"enable"`
		ListenIP                  string   `yaml:"listen-ip"`
		ListenPort                int      `yaml:"listen-port"`
		TLSSupport                bool     `yaml:"tls-support"`
		TLSMutual                 bool     `yaml:"tls-mutual"`
		TLSMinVersion             string   `yaml:"tls-min-version"`
		CertFile                  string   `yaml:"cert-file"`
		KeyFile                   string   `yaml:"key-file"`
		PromPrefix                string   `yaml:"prometheus-prefix"`
		LabelsList                []string `yaml:"prometheus-labels"`
		TopN                      int      `yaml:"top-n"`
		BasicAuthLogin            string   `yaml:"basic-auth-login"`
		BasicAuthPwd              string   `yaml:"basic-auth-pwd"`
		BasicAuthEnabled          bool     `yaml:"basic-auth-enable"`
		ChannelBufferSize         int      `yaml:"chan-buffer-size"`
		RequestersMetricsEnabled  bool     `yaml:"requesters-metrics-enabled"`
		DomainsMetricsEnabled     bool     `yaml:"domains-metrics-enabled"`
		NoErrorMetricsEnabled     bool     `yaml:"noerror-metrics-enabled"`
		ServfailMetricsEnabled    bool     `yaml:"servfail-metrics-enabled"`
		NonExistentMetricsEnabled bool     `yaml:"nonexistent-metrics-enabled"`
		TimeoutMetricsEnabled     bool     `yaml:"timeout-metrics-enabled"`
		HistogramMetricsEnabled   bool     `yaml:"histogram-metrics-enabled"`
		RequestersCacheTTL        int      `yaml:"requesters-cache-ttl"`
		RequestersCacheSize       int      `yaml:"requesters-cache-size"`
		DomainsCacheTTL           int      `yaml:"domains-cache-ttl"`
		DomainsCacheSize          int      `yaml:"domains-cache-size"`
		NoErrorDomainsCacheTTL    int      `yaml:"noerror-domains-cache-ttl"`
		NoErrorDomainsCacheSize   int      `yaml:"noerror-domains-cache-size"`
		ServfailDomainsCacheTTL   int      `yaml:"servfail-domains-cache-ttl"`
		ServfailDomainsCacheSize  int      `yaml:"servfail-domains-cache-size"`
		NXDomainsCacheTTL         int      `yaml:"nonexistent-domains-cache-ttl"`
		NXDomainsCacheSize        int      `yaml:"nonexistent-domains-cache-size"`
		DefaultDomainsCacheTTL    int      `yaml:"default-domains-cache-ttl"`
		DefaultDomainsCacheSize   int      `yaml:"default-domains-cache-size"`
	} `yaml:"prometheus"`
	RestAPI struct {
		Enable            bool   `yaml:"enable"`
		ListenIP          string `yaml:"listen-ip"`
		ListenPort        int    `yaml:"listen-port"`
		BasicAuthLogin    string `yaml:"basic-auth-login"`
		BasicAuthPwd      string `yaml:"basic-auth-pwd"`
		TLSSupport        bool   `yaml:"tls-support"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		TopN              int    `yaml:"top-n"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
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
		ChannelBufferSize   int    `yaml:"chan-buffer-size"`
	} `yaml:"logfile"`
	DNSTap struct {
		Enable            bool   `yaml:"enable"`
		RemoteAddress     string `yaml:"remote-address"`
		RemotePort        int    `yaml:"remote-port"`
		Transport         string `yaml:"transport"`
		SockPath          string `yaml:"sock-path"`
		ConnectTimeout    int    `yaml:"connect-timeout"`
		RetryInterval     int    `yaml:"retry-interval"`
		FlushInterval     int    `yaml:"flush-interval"`
		TLSSupport        bool   `yaml:"tls-support"`
		TLSInsecure       bool   `yaml:"tls-insecure"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CAFile            string `yaml:"ca-file"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		ServerID          string `yaml:"server-id"`
		OverwriteIdentity bool   `yaml:"overwrite-identity"`
		BufferSize        int    `yaml:"buffer-size"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"dnstapclient"`
	TCPClient struct {
		Enable            bool   `yaml:"enable"`
		RemoteAddress     string `yaml:"remote-address"`
		RemotePort        int    `yaml:"remote-port"`
		SockPath          string `yaml:"sock-path"` // deprecated
		RetryInterval     int    `yaml:"retry-interval"`
		Transport         string `yaml:"transport"`
		TLSSupport        bool   `yaml:"tls-support"` // deprecated
		TLSInsecure       bool   `yaml:"tls-insecure"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CAFile            string `yaml:"ca-file"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		Mode              string `yaml:"mode"`
		TextFormat        string `yaml:"text-format"`
		PayloadDelimiter  string `yaml:"delimiter"`
		BufferSize        int    `yaml:"buffer-size"`
		FlushInterval     int    `yaml:"flush-interval"`
		ConnectTimeout    int    `yaml:"connect-timeout"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"tcpclient"`
	Syslog struct {
		Enable            bool   `yaml:"enable"`
		Severity          string `yaml:"severity"`
		Facility          string `yaml:"facility"`
		Transport         string `yaml:"transport"`
		RemoteAddress     string `yaml:"remote-address"`
		RetryInterval     int    `yaml:"retry-interval"`
		TextFormat        string `yaml:"text-format"`
		Mode              string `yaml:"mode"`
		TLSInsecure       bool   `yaml:"tls-insecure"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CAFile            string `yaml:"ca-file"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		Formatter         string `yaml:"formatter"`
		Framer            string `yaml:"framer"`
		Hostname          string `yaml:"hostname"`
		AppName           string `yaml:"app-name"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
		Tag               string `yaml:"tag"`
		ReplaceNullChar   string `yaml:"replace-null-char"`
		FlushInterval     int    `yaml:"flush-interval"`
		BufferSize        int    `yaml:"buffer-size"`
	} `yaml:"syslog"`
	Fluentd struct {
		Enable            bool   `yaml:"enable"`
		RemoteAddress     string `yaml:"remote-address"`
		RemotePort        int    `yaml:"remote-port"`
		SockPath          string `yaml:"sock-path"` // deprecated
		ConnectTimeout    int    `yaml:"connect-timeout"`
		RetryInterval     int    `yaml:"retry-interval"`
		FlushInterval     int    `yaml:"flush-interval"`
		Transport         string `yaml:"transport"`
		TLSSupport        bool   `yaml:"tls-support"` // deprecated
		TLSInsecure       bool   `yaml:"tls-insecure"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CAFile            string `yaml:"ca-file"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		Tag               string `yaml:"tag"`
		BufferSize        int    `yaml:"buffer-size"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"fluentd"`
	InfluxDB struct {
		Enable            bool   `yaml:"enable"`
		ServerURL         string `yaml:"server-url"`
		AuthToken         string `yaml:"auth-token"`
		TLSSupport        bool   `yaml:"tls-support"`
		TLSInsecure       bool   `yaml:"tls-insecure"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CAFile            string `yaml:"ca-file"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		Bucket            string `yaml:"bucket"`
		Organization      string `yaml:"organization"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"influxdb"`
	LokiClient struct {
		Enable            bool              `yaml:"enable"`
		ServerURL         string            `yaml:"server-url"`
		JobName           string            `yaml:"job-name"`
		Mode              string            `yaml:"mode"`
		FlushInterval     int               `yaml:"flush-interval"`
		BatchSize         int               `yaml:"batch-size"`
		RetryInterval     int               `yaml:"retry-interval"`
		TextFormat        string            `yaml:"text-format"`
		ProxyURL          string            `yaml:"proxy-url"`
		TLSInsecure       bool              `yaml:"tls-insecure"`
		TLSMinVersion     string            `yaml:"tls-min-version"`
		CAFile            string            `yaml:"ca-file"`
		CertFile          string            `yaml:"cert-file"`
		KeyFile           string            `yaml:"key-file"`
		BasicAuthLogin    string            `yaml:"basic-auth-login"`
		BasicAuthPwd      string            `yaml:"basic-auth-pwd"`
		BasicAuthPwdFile  string            `yaml:"basic-auth-pwd-file"`
		TenantID          string            `yaml:"tenant-id"`
		RelabelConfigs    []*relabel.Config `yaml:"relabel-configs"`
		ChannelBufferSize int               `yaml:"chan-buffer-size"`
	} `yaml:"lokiclient"`
	Statsd struct {
		Enable            bool   `yaml:"enable"`
		Prefix            string `yaml:"prefix"`
		RemoteAddress     string `yaml:"remote-address"`
		RemotePort        int    `yaml:"remote-port"`
		ConnectTimeout    int    `yaml:"connect-timeout"`
		Transport         string `yaml:"transport"`
		FlushInterval     int    `yaml:"flush-interval"`
		TLSSupport        bool   `yaml:"tls-support"` // deprecated
		TLSInsecure       bool   `yaml:"tls-insecure"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CAFile            string `yaml:"ca-file"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"statsd"`
	ElasticSearchClient struct {
		Enable            bool   `yaml:"enable"`
		Index             string `yaml:"index"`
		Server            string `yaml:"server"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
		BulkSize          int    `yaml:"bulk-size"`
		FlushInterval     int    `yaml:"flush-interval"`
	} `yaml:"elasticsearch"`
	ScalyrClient struct {
		Enable            bool                   `yaml:"enable"`
		Mode              string                 `yaml:"mode"`
		TextFormat        string                 `yaml:"text-format"`
		SessionInfo       map[string]string      `yaml:"sessioninfo"`
		Attrs             map[string]interface{} `yaml:"attrs"`
		ServerURL         string                 `yaml:"server-url"`
		APIKey            string                 `yaml:"apikey"`
		Parser            string                 `yaml:"parser"`
		FlushInterval     int                    `yaml:"flush-interval"`
		ProxyURL          string                 `yaml:"proxy-url"`
		TLSInsecure       bool                   `yaml:"tls-insecure"`
		TLSMinVersion     string                 `yaml:"tls-min-version"`
		CAFile            string                 `yaml:"ca-file"`
		CertFile          string                 `yaml:"cert-file"`
		KeyFile           string                 `yaml:"key-file"`
		ChannelBufferSize int                    `yaml:"chan-buffer-size"`
	} `yaml:"scalyrclient"`
	RedisPub struct {
		Enable            bool   `yaml:"enable"`
		RemoteAddress     string `yaml:"remote-address"`
		RemotePort        int    `yaml:"remote-port"`
		SockPath          string `yaml:"sock-path"` // deprecated
		RetryInterval     int    `yaml:"retry-interval"`
		Transport         string `yaml:"transport"`
		TLSSupport        bool   `yaml:"tls-support"` // deprecated
		TLSInsecure       bool   `yaml:"tls-insecure"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CAFile            string `yaml:"ca-file"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		Mode              string `yaml:"mode"`
		TextFormat        string `yaml:"text-format"`
		PayloadDelimiter  string `yaml:"delimiter"`
		BufferSize        int    `yaml:"buffer-size"`
		FlushInterval     int    `yaml:"flush-interval"`
		ConnectTimeout    int    `yaml:"connect-timeout"`
		RedisChannel      string `yaml:"redis-channel"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"redispub"`
	KafkaProducer struct {
		Enable            bool   `yaml:"enable"`
		RemoteAddress     string `yaml:"remote-address"`
		RemotePort        int    `yaml:"remote-port"`
		RetryInterval     int    `yaml:"retry-interval"`
		TLSSupport        bool   `yaml:"tls-support"`
		TLSInsecure       bool   `yaml:"tls-insecure"`
		TLSMinVersion     string `yaml:"tls-min-version"`
		CAFile            string `yaml:"ca-file"`
		CertFile          string `yaml:"cert-file"`
		KeyFile           string `yaml:"key-file"`
		SaslSupport       bool   `yaml:"sasl-support"`
		SaslUsername      string `yaml:"sasl-username"`
		SaslPassword      string `yaml:"sasl-password"`
		SaslMechanism     string `yaml:"sasl-mechanism"`
		Mode              string `yaml:"mode"`
		BufferSize        int    `yaml:"buffer-size"`
		FlushInterval     int    `yaml:"flush-interval"`
		ConnectTimeout    int    `yaml:"connect-timeout"`
		Topic             string `yaml:"topic"`
		Partition         int    `yaml:"partition"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
		Compression       string `yaml:"compression"`
	} `yaml:"kafkaproducer"`
	FalcoClient struct {
		Enable            bool   `yaml:"enable"`
		URL               string `yaml:"url"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"falco"`
}

func (c *ConfigLoggers) SetDefault() {
	c.Stdout.Enable = false
	c.Stdout.Mode = ModeText
	c.Stdout.TextFormat = ""
	c.Stdout.ChannelBufferSize = 65535

	c.DNSTap.Enable = false
	c.DNSTap.RemoteAddress = LocalhostIP
	c.DNSTap.RemotePort = 6000
	c.DNSTap.Transport = netlib.SocketTCP
	c.DNSTap.ConnectTimeout = 5
	c.DNSTap.RetryInterval = 10
	c.DNSTap.FlushInterval = 30
	c.DNSTap.SockPath = ""
	c.DNSTap.TLSSupport = false
	c.DNSTap.TLSInsecure = false
	c.DNSTap.TLSMinVersion = TLSV12
	c.DNSTap.CAFile = ""
	c.DNSTap.CertFile = ""
	c.DNSTap.KeyFile = ""
	c.DNSTap.ServerID = ""
	c.DNSTap.OverwriteIdentity = false
	c.DNSTap.BufferSize = 100
	c.DNSTap.ChannelBufferSize = 65535

	c.LogFile.Enable = false
	c.LogFile.FilePath = ""
	c.LogFile.FlushInterval = 10
	c.LogFile.MaxSize = 100
	c.LogFile.MaxFiles = 10
	c.LogFile.Compress = false
	c.LogFile.CompressInterval = 60
	c.LogFile.CompressPostCommand = ""
	c.LogFile.Mode = ModeText
	c.LogFile.PostRotateCommand = ""
	c.LogFile.PostRotateDelete = false
	c.LogFile.TextFormat = ""
	c.LogFile.ChannelBufferSize = 65535

	c.Prometheus.Enable = false
	c.Prometheus.ListenIP = LocalhostIP
	c.Prometheus.ListenPort = 8081
	c.Prometheus.TLSSupport = false
	c.Prometheus.TLSMutual = false
	c.Prometheus.TLSMinVersion = TLSV12
	c.Prometheus.CertFile = ""
	c.Prometheus.KeyFile = ""
	c.Prometheus.PromPrefix = ProgName
	c.Prometheus.TopN = 10
	c.Prometheus.BasicAuthLogin = "admin"
	c.Prometheus.BasicAuthPwd = "changeme"
	c.Prometheus.BasicAuthEnabled = true
	c.Prometheus.ChannelBufferSize = 65535
	c.Prometheus.HistogramMetricsEnabled = false
	c.Prometheus.RequestersMetricsEnabled = true
	c.Prometheus.DomainsMetricsEnabled = true
	c.Prometheus.NoErrorMetricsEnabled = true
	c.Prometheus.ServfailMetricsEnabled = true
	c.Prometheus.NonExistentMetricsEnabled = true
	c.Prometheus.RequestersCacheTTL = 3600
	c.Prometheus.RequestersCacheSize = 250000
	c.Prometheus.DomainsCacheTTL = 3600
	c.Prometheus.DomainsCacheSize = 500000
	c.Prometheus.DomainsCacheTTL = 3600
	c.Prometheus.NoErrorDomainsCacheSize = 100000
	c.Prometheus.NoErrorDomainsCacheTTL = 3600
	c.Prometheus.ServfailDomainsCacheSize = 10000
	c.Prometheus.ServfailDomainsCacheTTL = 3600
	c.Prometheus.NXDomainsCacheSize = 10000
	c.Prometheus.NXDomainsCacheTTL = 3600
	c.Prometheus.DefaultDomainsCacheSize = 1000
	c.Prometheus.DefaultDomainsCacheTTL = 3600

	c.RestAPI.Enable = false
	c.RestAPI.ListenIP = LocalhostIP
	c.RestAPI.ListenPort = 8080
	c.RestAPI.BasicAuthLogin = "admin"
	c.RestAPI.BasicAuthPwd = "changeme"
	c.RestAPI.TLSSupport = false
	c.RestAPI.TLSMinVersion = TLSV12
	c.RestAPI.CertFile = ""
	c.RestAPI.KeyFile = ""
	c.RestAPI.TopN = 100
	c.RestAPI.ChannelBufferSize = 65535

	c.TCPClient.Enable = false
	c.TCPClient.RemoteAddress = LocalhostIP
	c.TCPClient.RemotePort = 9999
	c.TCPClient.SockPath = ""
	c.TCPClient.RetryInterval = 10
	c.TCPClient.Transport = netlib.SocketTCP
	c.TCPClient.TLSSupport = false
	c.TCPClient.TLSInsecure = false
	c.TCPClient.TLSMinVersion = TLSV12
	c.TCPClient.CAFile = ""
	c.TCPClient.CertFile = ""
	c.TCPClient.KeyFile = ""
	c.TCPClient.Mode = ModeFlatJSON
	c.TCPClient.TextFormat = ""
	c.TCPClient.PayloadDelimiter = "\n"
	c.TCPClient.BufferSize = 100
	c.TCPClient.ConnectTimeout = 5
	c.TCPClient.FlushInterval = 30
	c.TCPClient.ChannelBufferSize = 65535

	c.Syslog.Enable = false
	c.Syslog.Severity = "INFO"
	c.Syslog.Facility = "DAEMON"
	c.Syslog.Transport = "local"
	c.Syslog.RemoteAddress = "127.0.0.1:514"
	c.Syslog.TextFormat = ""
	c.Syslog.Mode = ModeText
	c.Syslog.RetryInterval = 10
	c.Syslog.TLSInsecure = false
	c.Syslog.TLSMinVersion = TLSV12
	c.Syslog.CAFile = ""
	c.Syslog.CertFile = ""
	c.Syslog.KeyFile = ""
	c.Syslog.ChannelBufferSize = 65535
	c.Syslog.Tag = ""
	c.Syslog.Framer = ""
	c.Syslog.Formatter = "rfc5424"
	c.Syslog.Hostname = ""
	c.Syslog.AppName = "DNScollector"
	c.Syslog.ReplaceNullChar = "�"
	c.Syslog.FlushInterval = 30
	c.Syslog.BufferSize = 100

	c.Fluentd.Enable = false
	c.Fluentd.RemoteAddress = LocalhostIP
	c.Fluentd.RemotePort = 24224
	c.Fluentd.SockPath = "" // deprecated
	c.Fluentd.RetryInterval = 10
	c.Fluentd.ConnectTimeout = 5
	c.Fluentd.FlushInterval = 30
	c.Fluentd.Transport = netlib.SocketTCP
	c.Fluentd.TLSSupport = false // deprecated
	c.Fluentd.TLSInsecure = false
	c.Fluentd.TLSMinVersion = TLSV12
	c.Fluentd.CAFile = ""
	c.Fluentd.CertFile = ""
	c.Fluentd.KeyFile = ""
	c.Fluentd.Tag = "dns.collector"
	c.Fluentd.BufferSize = 100
	c.Fluentd.ChannelBufferSize = 65535

	c.InfluxDB.Enable = false
	c.InfluxDB.ServerURL = "http://localhost:8086"
	c.InfluxDB.AuthToken = ""
	c.InfluxDB.TLSSupport = false
	c.InfluxDB.TLSInsecure = false
	c.InfluxDB.TLSMinVersion = TLSV12
	c.InfluxDB.CAFile = ""
	c.InfluxDB.CertFile = ""
	c.InfluxDB.KeyFile = ""
	c.InfluxDB.Bucket = ""
	c.InfluxDB.Organization = ""
	c.InfluxDB.ChannelBufferSize = 65535

	c.LokiClient.Enable = false
	c.LokiClient.ServerURL = "http://localhost:3100/loki/api/v1/push"
	c.LokiClient.JobName = ProgName
	c.LokiClient.Mode = ModeText
	c.LokiClient.FlushInterval = 5
	c.LokiClient.BatchSize = 1024 * 1024
	c.LokiClient.RetryInterval = 10
	c.LokiClient.TextFormat = ""
	c.LokiClient.ProxyURL = ""
	c.LokiClient.TLSInsecure = false
	c.LokiClient.TLSMinVersion = TLSV12
	c.LokiClient.CAFile = ""
	c.LokiClient.CertFile = ""
	c.LokiClient.KeyFile = ""
	c.LokiClient.BasicAuthLogin = ""
	c.LokiClient.BasicAuthPwd = ""
	c.LokiClient.BasicAuthPwdFile = ""
	c.LokiClient.TenantID = ""
	c.LokiClient.ChannelBufferSize = 65535

	c.Statsd.Enable = false
	c.Statsd.Prefix = ProgName
	c.Statsd.RemoteAddress = LocalhostIP
	c.Statsd.RemotePort = 8125
	c.Statsd.Transport = netlib.SocketUDP
	c.Statsd.ConnectTimeout = 5
	c.Statsd.FlushInterval = 10
	c.Statsd.TLSSupport = false // deprecated
	c.Statsd.TLSInsecure = false
	c.Statsd.TLSMinVersion = TLSV12
	c.Statsd.CAFile = ""
	c.Statsd.CertFile = ""
	c.Statsd.KeyFile = ""
	c.Statsd.ChannelBufferSize = 65535

	c.ElasticSearchClient.Enable = false
	c.ElasticSearchClient.Server = "http://127.0.0.1:9200/"
	c.ElasticSearchClient.Index = ""
	c.ElasticSearchClient.ChannelBufferSize = 65535
	c.ElasticSearchClient.BulkSize = 100
	c.ElasticSearchClient.FlushInterval = 10

	c.RedisPub.Enable = false
	c.RedisPub.RemoteAddress = LocalhostIP
	c.RedisPub.RemotePort = 6379
	c.RedisPub.SockPath = ""
	c.RedisPub.RetryInterval = 10
	c.RedisPub.Transport = netlib.SocketTCP
	c.RedisPub.TLSSupport = false
	c.RedisPub.TLSInsecure = false
	c.RedisPub.TLSMinVersion = TLSV12
	c.RedisPub.CAFile = ""
	c.RedisPub.CertFile = ""
	c.RedisPub.KeyFile = ""
	c.RedisPub.Mode = ModeFlatJSON
	c.RedisPub.TextFormat = ""
	c.RedisPub.PayloadDelimiter = "\n"
	c.RedisPub.BufferSize = 100
	c.RedisPub.ConnectTimeout = 5
	c.RedisPub.FlushInterval = 30
	c.RedisPub.RedisChannel = "dns_collector"
	c.RedisPub.ChannelBufferSize = 65535

	c.KafkaProducer.Enable = false
	c.KafkaProducer.RemoteAddress = LocalhostIP
	c.KafkaProducer.RemotePort = 9092
	c.KafkaProducer.RetryInterval = 10
	c.KafkaProducer.TLSSupport = false
	c.KafkaProducer.TLSInsecure = false
	c.KafkaProducer.TLSMinVersion = TLSV12
	c.KafkaProducer.CAFile = ""
	c.KafkaProducer.CertFile = ""
	c.KafkaProducer.KeyFile = ""
	c.KafkaProducer.SaslSupport = false
	c.KafkaProducer.SaslUsername = ""
	c.KafkaProducer.SaslPassword = ""
	c.KafkaProducer.SaslMechanism = SASLMechanismPlain
	c.KafkaProducer.Mode = ModeFlatJSON
	c.KafkaProducer.BufferSize = 100
	c.KafkaProducer.ConnectTimeout = 5
	c.KafkaProducer.FlushInterval = 10
	c.KafkaProducer.Topic = "dnscollector"
	c.KafkaProducer.Partition = 0
	c.KafkaProducer.ChannelBufferSize = 65535
	c.KafkaProducer.Compression = CompressNone

	c.FalcoClient.Enable = false
	c.FalcoClient.URL = "http://127.0.0.1:9200"
	c.FalcoClient.ChannelBufferSize = 65535
}

func (c *ConfigLoggers) GetTags() (ret []string) {
	cl := reflect.TypeOf(*c)

	for i := 0; i < cl.NumField(); i++ {
		field := cl.Field(i)
		tag := field.Tag.Get("yaml")
		ret = append(ret, tag)
	}
	return ret
}

func (c *ConfigLoggers) IsValid(name string) bool {
	tags := c.GetTags()
	for i := range tags {
		if name == tags[i] {
			return true
		}
	}
	return false
}
