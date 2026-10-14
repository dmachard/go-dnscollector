package config

import (
	"reflect"

	"github.com/creasty/defaults"
	"github.com/prometheus/prometheus/model/relabel"
)

type LoggerDevNull struct {
	Enable bool `yaml:"enable" default:"false"`
}

type LoggerStdout struct {
	Enable               bool    `yaml:"enable" default:"false"`
	Mode                 string  `yaml:"mode" default:"text"`
	TextFormat           string  `yaml:"text-format" default:""`
	JinjaFormat          string  `yaml:"jinja-format" default:""`
	OverwriteDNSPortPcap bool    `yaml:"overwrite-dns-port-pcap" default:"false"`
	WriterBufferSize     int     `yaml:"writer-buffer-size" default:"65536"`
	FlushInterval        float64 `yaml:"flush-interval" default:"1.0"`
}

type LoggerPrometheus struct {
	Enable                     bool     `yaml:"enable" default:"false"`
	ListenIP                   string   `yaml:"listen-ip" default:"127.0.0.1"`
	ListenPort                 int      `yaml:"listen-port" default:"8081"`
	TLSSupport                 bool     `yaml:"tls-support" default:"false"`
	TLSMutual                  bool     `yaml:"tls-mutual" default:"false"`
	TLSMinVersion              string   `yaml:"tls-min-version" default:"1.2"`
	CertFile                   string   `yaml:"cert-file" default:""`
	KeyFile                    string   `yaml:"key-file" default:""`
	PromPrefix                 string   `yaml:"prometheus-prefix" default:"dnscollector"`
	LabelsList                 []string `yaml:"prometheus-labels" default:"[]"`
	TopN                       int      `yaml:"top-n" default:"10"`
	BasicAuthLogin             string   `yaml:"basic-auth-login" default:"admin"`
	BasicAuthPwd               string   `yaml:"basic-auth-pwd" default:"changeme"`
	BasicAuthEnabled           bool     `yaml:"basic-auth-enable" default:"true"`
	RequestersMetricsEnabled   bool     `yaml:"requesters-metrics-enabled" default:"true"`
	DomainsMetricsEnabled      bool     `yaml:"domains-metrics-enabled" default:"true"`
	NoErrorMetricsEnabled      bool     `yaml:"noerror-metrics-enabled" default:"true"`
	ServfailMetricsEnabled     bool     `yaml:"servfail-metrics-enabled" default:"true"`
	NonExistentMetricsEnabled  bool     `yaml:"nonexistent-metrics-enabled" default:"true"`
	TLDsMetricsEnabled         bool     `yaml:"tlds-metrics-enabled" default:"false"`
	SuspiciousMetricsEnabled   bool     `yaml:"suspicious-metrics-enabled" default:"false"`
	TimeoutMetricsEnabled      bool     `yaml:"timeout-metrics-enabled" default:"false"`
	HistogramMetricsEnabled    bool     `yaml:"histogram-metrics-enabled" default:"false"`
	TopCountriesMetricsEnabled bool     `yaml:"top-countries-metrics-enabled" default:"false"`
	TopASNsMetricsEnabled      bool     `yaml:"top-asns-metrics-enabled" default:"false"`
	RequestersCacheTTL         int      `yaml:"requesters-cache-ttl" default:"3600"`
	RequestersCacheSize        int      `yaml:"requesters-cache-size" default:"250000"`
	DomainsCacheTTL            int      `yaml:"domains-cache-ttl" default:"3600"`
	DomainsCacheSize           int      `yaml:"domains-cache-size" default:"500000"`
	NoErrorDomainsCacheTTL     int      `yaml:"noerror-domains-cache-ttl" default:"3600"`
	NoErrorDomainsCacheSize    int      `yaml:"noerror-domains-cache-size" default:"100000"`
	ServfailDomainsCacheTTL    int      `yaml:"servfail-domains-cache-ttl" default:"3600"`
	ServfailDomainsCacheSize   int      `yaml:"servfail-domains-cache-size" default:"10000"`
	NXDomainsCacheTTL          int      `yaml:"nonexistent-domains-cache-ttl" default:"3600"`
	NXDomainsCacheSize         int      `yaml:"nonexistent-domains-cache-size" default:"10000"`
	DefaultDomainsCacheTTL     int      `yaml:"default-domains-cache-ttl" default:"3600"`
	DefaultDomainsCacheSize    int      `yaml:"default-domains-cache-size" default:"1000"`
}

type LoggerRestAPI struct {
	Enable                   bool   `yaml:"enable" default:"false"`
	ListenIP                 string `yaml:"listen-ip" default:"127.0.0.1"`
	ListenPort               int    `yaml:"listen-port" default:"8080"`
	BasicAuthLogin           string `yaml:"basic-auth-login" default:"admin"`
	BasicAuthPwd             string `yaml:"basic-auth-pwd" default:"changeme"`
	TLSSupport               bool   `yaml:"tls-support" default:"false"`
	TLSMinVersion            string `yaml:"tls-min-version" default:"1.2"`
	CertFile                 string `yaml:"cert-file" default:""`
	KeyFile                  string `yaml:"key-file" default:""`
	TopN                     int    `yaml:"top-n" default:"100"`
	RequestersCacheTTL       int    `yaml:"requesters-cache-ttl" default:"3600"`
	RequestersCacheSize      int    `yaml:"requesters-cache-size" default:"250000"`
	DomainsCacheTTL          int    `yaml:"domains-cache-ttl" default:"3600"`
	DomainsCacheSize         int    `yaml:"domains-cache-size" default:"500000"`
	NXDomainsCacheTTL        int    `yaml:"nonexistent-domains-cache-ttl" default:"3600"`
	NXDomainsCacheSize       int    `yaml:"nonexistent-domains-cache-size" default:"10000"`
	ServfailDomainsCacheTTL  int    `yaml:"servfail-domains-cache-ttl" default:"3600"`
	ServfailDomainsCacheSize int    `yaml:"servfail-domains-cache-size" default:"10000"`
	TLDsCacheTTL             int    `yaml:"tlds-cache-ttl" default:"3600"`
	TLDsCacheSize            int    `yaml:"tlds-cache-size" default:"10000"`
	SuspiciousCacheTTL       int    `yaml:"suspicious-cache-ttl" default:"3600"`
	SuspiciousCacheSize      int    `yaml:"suspicious-cache-size" default:"10000"`
}

type LoggerLogFile struct {
	Enable               bool   `yaml:"enable" default:"false"`
	FilePath             string `yaml:"file-path" default:""`
	MaxSize              int    `yaml:"max-size" default:"100"`
	MaxFiles             int    `yaml:"max-files" default:"10"`
	MaxBatchSize         int    `yaml:"max-batch-size" default:"65536"`
	RotationInterval     int    `yaml:"rotation-interval" default:"0"`
	FlushInterval        int    `yaml:"flush-interval" default:"1"`
	Compress             bool   `yaml:"compress" default:"false"`
	Mode                 string `yaml:"mode" default:"text"`
	PostRotateCommand    string `yaml:"postrotate-command" default:""`
	PostRotateDelete     bool   `yaml:"postrotate-delete-success" default:"false"`
	TextFormat           string `yaml:"text-format" default:""`
	JinjaFormat          string `yaml:"jinja-format" default:""`
	ExtendedSupport      bool   `yaml:"extended-support" default:"false"`
	OverwriteDNSPortPcap bool   `yaml:"overwrite-dns-port-pcap" default:"false"`
}

type LoggerDNSTap struct {
	Enable            bool   `yaml:"enable" default:"false"`
	RemoteAddress     string `yaml:"remote-address" default:"127.0.0.1"`
	RemotePort        int    `yaml:"remote-port" default:"6000"`
	Transport         string `yaml:"transport" default:"tcp"`
	SockPath          string `yaml:"sock-path" default:""`
	ConnectTimeout    int    `yaml:"connect-timeout" default:"5"`
	RetryInterval     int    `yaml:"retry-interval" default:"10"`
	FlushInterval     int    `yaml:"flush-interval" default:"30"`
	TLSSupport        bool   `yaml:"tls-support" default:"false"`
	TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
	CAFile            string `yaml:"ca-file" default:""`
	CertFile          string `yaml:"cert-file" default:""`
	KeyFile           string `yaml:"key-file" default:""`
	ServerID          string `yaml:"server-id" default:""`
	OverwriteIdentity bool   `yaml:"overwrite-identity" default:"false"`
	BufferSize        int    `yaml:"buffer-size" default:"100"`
	ExtendedSupport   bool   `yaml:"extended-support" default:"false"`
	Compression       string `yaml:"compression" default:"none"`
}

type LoggerTCPClient struct {
	Enable           bool   `yaml:"enable" default:"false"`
	RemoteAddress    string `yaml:"remote-address" default:"127.0.0.1"`
	RemotePort       int    `yaml:"remote-port" default:"9999"`
	RetryInterval    int    `yaml:"retry-interval" default:"10"`
	Transport        string `yaml:"transport" default:"tcp"`
	TLSInsecure      bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion    string `yaml:"tls-min-version" default:"1.2"`
	CAFile           string `yaml:"ca-file" default:""`
	CertFile         string `yaml:"cert-file" default:""`
	KeyFile          string `yaml:"key-file" default:""`
	Mode             string `yaml:"mode" default:"flat-json"`
	TextFormat       string `yaml:"text-format" default:""`
	PayloadDelimiter string `yaml:"delimiter" default:"\n"`
	BufferSize       int    `yaml:"buffer-size" default:"100"`
	FlushInterval    int    `yaml:"flush-interval" default:"30"`
	ConnectTimeout   int    `yaml:"connect-timeout" default:"5"`
}

type LoggerSyslog struct {
	Enable          bool   `yaml:"enable" default:"false"`
	Severity        string `yaml:"severity" default:"INFO"`
	Facility        string `yaml:"facility" default:"DAEMON"`
	Transport       string `yaml:"transport" default:"local"`
	RemoteAddress   string `yaml:"remote-address" default:"127.0.0.1:514"`
	RetryInterval   int    `yaml:"retry-interval" default:"10"`
	TextFormat      string `yaml:"text-format" default:""`
	Mode            string `yaml:"mode" default:"text"`
	TLSInsecure     bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion   string `yaml:"tls-min-version" default:"1.2"`
	CAFile          string `yaml:"ca-file" default:""`
	CertFile        string `yaml:"cert-file" default:""`
	KeyFile         string `yaml:"key-file" default:""`
	Formatter       string `yaml:"formatter" default:"rfc5424"`
	Framer          string `yaml:"framer" default:""`
	Hostname        string `yaml:"hostname" default:""`
	AppName         string `yaml:"app-name" default:"DNScollector"`
	Tag             string `yaml:"tag" default:""`
	ReplaceNullChar string `yaml:"replace-null-char" default:"\ufffd"`
	FlushInterval   int    `yaml:"flush-interval" default:"30"`
	BufferSize      int    `yaml:"buffer-size" default:"100"`
}

type LoggerFluentd struct {
	Enable         bool   `yaml:"enable" default:"false"`
	RemoteAddress  string `yaml:"remote-address" default:"127.0.0.1"`
	RemotePort     int    `yaml:"remote-port" default:"24224"`
	ConnectTimeout int    `yaml:"connect-timeout" default:"5"`
	RetryInterval  int    `yaml:"retry-interval" default:"10"`
	FlushInterval  int    `yaml:"flush-interval" default:"30"`
	Transport      string `yaml:"transport" default:"tcp"`
	TLSInsecure    bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion  string `yaml:"tls-min-version" default:"1.2"`
	CAFile         string `yaml:"ca-file" default:""`
	CertFile       string `yaml:"cert-file" default:""`
	KeyFile        string `yaml:"key-file" default:""`
	Tag            string `yaml:"tag" default:"dns.collector"`
	BufferSize     int    `yaml:"buffer-size" default:"100"`
}

type LoggerInfluxDB struct {
	Enable        bool   `yaml:"enable" default:"false"`
	ServerURL     string `yaml:"server-url" default:"http://localhost:8086"`
	AuthToken     string `yaml:"auth-token" default:""`
	TLSSupport    bool   `yaml:"tls-support" default:"false"`
	TLSInsecure   bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion string `yaml:"tls-min-version" default:"1.2"`
	CAFile        string `yaml:"ca-file" default:""`
	CertFile      string `yaml:"cert-file" default:""`
	KeyFile       string `yaml:"key-file" default:""`
	Bucket        string `yaml:"bucket" default:""`
	Organization  string `yaml:"organization" default:""`
}

type LoggerLokiClient struct {
	Enable           bool              `yaml:"enable" default:"false"`
	ServerURL        string            `yaml:"server-url" default:"http://localhost:3100/loki/api/v1/push"`
	JobName          string            `yaml:"job-name" default:"dnscollector"`
	Mode             string            `yaml:"mode" default:"text"`
	FlushInterval    int               `yaml:"flush-interval" default:"5"`
	BatchSize        int               `yaml:"batch-size" default:"1048576"`
	RetryInterval    int               `yaml:"retry-interval" default:"10"`
	TextFormat       string            `yaml:"text-format" default:""`
	ProxyURL         string            `yaml:"proxy-url" default:""`
	TLSInsecure      bool              `yaml:"tls-insecure" default:"false"`
	TLSMinVersion    string            `yaml:"tls-min-version" default:"1.2"`
	CAFile           string            `yaml:"ca-file" default:""`
	CertFile         string            `yaml:"cert-file" default:""`
	KeyFile          string            `yaml:"key-file" default:""`
	BasicAuthLogin   string            `yaml:"basic-auth-login" default:""`
	BasicAuthPwd     string            `yaml:"basic-auth-pwd" default:""`
	BasicAuthPwdFile string            `yaml:"basic-auth-pwd-file" default:""`
	TenantID         string            `yaml:"tenant-id" default:""`
	RelabelConfigs   []*relabel.Config `yaml:"relabel-configs" default:"[]"`
}

type LoggerStatsd struct {
	Enable         bool   `yaml:"enable" default:"false"`
	Prefix         string `yaml:"prefix" default:"dnscollector"`
	RemoteAddress  string `yaml:"remote-address" default:"127.0.0.1"`
	RemotePort     int    `yaml:"remote-port" default:"8125"`
	ConnectTimeout int    `yaml:"connect-timeout" default:"5"`
	Transport      string `yaml:"transport" default:"udp"`
	FlushInterval  int    `yaml:"flush-interval" default:"10"`
	CertFile       string `yaml:"cert-file" default:""`
	TLSInsecure    bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion  string `yaml:"tls-min-version" default:"1.2"`
	CAFile         string `yaml:"ca-file" default:""`
	KeyFile        string `yaml:"key-file" default:""`
}

type LoggerNsq struct {
	Enable bool   `yaml:"enable" default:"false"`
	Host   string `yaml:"host" default:"127.0.0.1"`
	Port   int    `yaml:"port" default:"4150"`
	Topic  string `yaml:"topic" default:"dnscollector"`
}

type LoggerElasticSearchClient struct {
	Enable            bool   `yaml:"enable" default:"false"`
	Index             string `yaml:"index" default:"dnscollector"`
	Server            string `yaml:"server" default:"http://127.0.0.1:9200/"`
	BulkSize          int    `yaml:"bulk-size" default:"5242880"`
	BulkChannelSize   int    `yaml:"bulk-channel-size" default:"10"`
	FlushInterval     int    `yaml:"flush-interval" default:"10"`
	Compression       string `yaml:"compression" default:"none"`
	BasicAuthEnabled  bool   `yaml:"basic-auth-enable" default:"false"`
	BasicAuthLogin    string `yaml:"basic-auth-login" default:""`
	BasicAuthPwd      string `yaml:"basic-auth-pwd" default:""`
	RetryEnabled      bool   `yaml:"retry-enable" default:"true"`
	RetryMaxAttempts  int    `yaml:"retry-max-attempts" default:"5"`
	RetryInitialDelay int    `yaml:"retry-initial-delay" default:"1"`
	RetryMaxDelay     int    `yaml:"retry-max-delay" default:"30"`
	TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
	CAFile            string `yaml:"ca-file" default:""`
	CertFile          string `yaml:"cert-file" default:""`
	KeyFile           string `yaml:"key-file" default:""`
}

type LoggerOpenTelemetryClient struct {
	Enable               bool   `yaml:"enable" default:"false"`
	CleanupSpansInterval int    `yaml:"cleanup-spans-interval" default:"30"`
	MaxSpanTime          int    `yaml:"max-span-time" default:"120"`
	OtelEndpoint         string `yaml:"otel-endpoint" default:""`
}

type LoggerScalyrClient struct {
	Enable        bool                   `yaml:"enable" default:"false"`
	Mode          string                 `yaml:"mode" default:"text"`
	TextFormat    string                 `yaml:"text-format" default:""`
	SessionInfo   map[string]string      `yaml:"sessioninfo" default:"{}"`
	Attrs         map[string]interface{} `yaml:"attrs" default:"{}"`
	ServerURL     string                 `yaml:"server-url" default:"app.scalyr.com"`
	APIKey        string                 `yaml:"apikey" default:""`
	Parser        string                 `yaml:"parser" default:""`
	FlushInterval int                    `yaml:"flush-interval" default:"10"`
	ProxyURL      string                 `yaml:"proxy-url" default:""`
	TLSInsecure   bool                   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion string                 `yaml:"tls-min-version" default:"1.2"`
	CAFile        string                 `yaml:"ca-file" default:""`
	CertFile      string                 `yaml:"cert-file" default:""`
	KeyFile       string                 `yaml:"key-file" default:""`
}

type LoggerRedisPub struct {
	Enable           bool   `yaml:"enable" default:"false"`
	RemoteAddress    string `yaml:"remote-address" default:"127.0.0.1"`
	RemotePort       int    `yaml:"remote-port" default:"6379"`
	RetryInterval    int    `yaml:"retry-interval" default:"10"`
	Transport        string `yaml:"transport" default:"tcp"`
	TLSInsecure      bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion    string `yaml:"tls-min-version" default:"1.2"`
	CAFile           string `yaml:"ca-file" default:""`
	CertFile         string `yaml:"cert-file" default:""`
	KeyFile          string `yaml:"key-file" default:""`
	Mode             string `yaml:"mode" default:"flat-json"`
	TextFormat       string `yaml:"text-format" default:""`
	PayloadDelimiter string `yaml:"delimiter" default:"\n"`
	BufferSize       int    `yaml:"buffer-size" default:"100"`
	FlushInterval    int    `yaml:"flush-interval" default:"30"`
	ConnectTimeout   int    `yaml:"connect-timeout" default:"5"`
	RedisChannel     string `yaml:"redis-channel" default:"dns_collector"`
}

type LoggerKafkaProducer struct {
	Enable         bool   `yaml:"enable" default:"false"`
	ClientID       string `yaml:"client-id" default:""`
	RemoteAddress  string `yaml:"remote-address" default:"127.0.0.1"`
	RemotePort     int    `yaml:"remote-port" default:"9092"`
	TLSSupport     bool   `yaml:"tls-support" default:"false"`
	TLSInsecure    bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion  string `yaml:"tls-min-version" default:"1.2"`
	CAFile         string `yaml:"ca-file" default:""`
	CertFile       string `yaml:"cert-file" default:""`
	KeyFile        string `yaml:"key-file" default:""`
	SaslSupport    bool   `yaml:"sasl-support" default:"false"`
	SaslUsername   string `yaml:"sasl-username" default:""`
	SaslPassword   string `yaml:"sasl-password" default:""`
	SaslMechanism  string `yaml:"sasl-mechanism" default:"PLAIN"`
	Mode           string `yaml:"mode" default:"flat-json"`
	TextFormat     string `yaml:"text-format" default:""`
	BatchSize      int    `yaml:"batch-size" default:"100"`
	FlushInterval  int    `yaml:"flush-interval" default:"10"`
	ConnectTimeout int    `yaml:"connect-timeout" default:"5"`
	Topic          string `yaml:"topic" default:"dnscollector"`
	Partition      *int   `yaml:"partition" default:"-"`
	Balancer       string `yaml:"balancer" default:"round-robin"`
	Compression    string `yaml:"compression" default:"none"`
}

type LoggerFalcoClient struct {
	Enable bool   `yaml:"enable" default:"false"`
	URL    string `yaml:"url" default:"http://127.0.0.1:9200"`
}

type LoggerClickhouseClient struct {
	Enable        bool   `yaml:"enable" default:"false"`
	URL           string `yaml:"url" default:"http://localhost:8123"`
	User          string `yaml:"user" default:"default"`
	Password      string `yaml:"password" default:"password"`
	Database      string `yaml:"database" default:"dnscollector"`
	Table         string `yaml:"table" default:"records"`
	BufferSize    int    `yaml:"buffer-size" default:"100"`
	FlushInterval int    `yaml:"flush-interval" default:"10"`
	Timeout       int    `yaml:"timeout" default:"5"`
	TLSSupport    bool   `yaml:"tls-support" default:"false"`
	TLSInsecure   bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion string `yaml:"tls-min-version" default:"1.2"`
	CAFile        string `yaml:"ca-file" default:""`
	CertFile      string `yaml:"cert-file" default:""`
	KeyFile       string `yaml:"key-file" default:""`
}

type LoggerMQTT struct {
	Enable          bool   `yaml:"enable" default:"false"`
	RemoteAddress   string `yaml:"remote-address" default:"127.0.0.1"`
	RemotePort      int    `yaml:"remote-port" default:"1883"`
	ConnectTimeout  int    `yaml:"connect-timeout" default:"5"`
	RetryInterval   int    `yaml:"retry-interval" default:"10"`
	Topic           string `yaml:"topic" default:"dnscollector/dns"`
	QOS             byte   `yaml:"qos" default:"0"`
	Mode            string `yaml:"mode" default:"flat-json"`
	TextFormat      string `yaml:"text-format" default:""`
	BufferSize      int    `yaml:"buffer-size" default:"100"`
	FlushInterval   int    `yaml:"flush-interval" default:"30"`
	ProtocolVersion string `yaml:"protocol-version" default:"auto"`
	Username        string `yaml:"username" default:""`
	Password        string `yaml:"password" default:""`
	TLSSupport      bool   `yaml:"tls-support" default:"false"`
	TLSInsecure     bool   `yaml:"tls-insecure" default:"false"`
	TLSMinVersion   string `yaml:"tls-min-version" default:"1.2"`
	CAFile          string `yaml:"ca-file" default:""`
	CertFile        string `yaml:"cert-file" default:""`
	KeyFile         string `yaml:"key-file" default:""`
}

type ConfigLoggers struct {
	DevNull             LoggerDevNull             `yaml:"devnull"`
	Stdout              LoggerStdout              `yaml:"stdout"`
	Prometheus          LoggerPrometheus          `yaml:"prometheus"`
	RestAPI             LoggerRestAPI             `yaml:"restapi"`
	LogFile             LoggerLogFile             `yaml:"logfile"`
	DNSTap              LoggerDNSTap              `yaml:"dnstapclient"`
	TCPClient           LoggerTCPClient           `yaml:"tcpclient"`
	Syslog              LoggerSyslog              `yaml:"syslog"`
	Fluentd             LoggerFluentd             `yaml:"fluentd"`
	InfluxDB            LoggerInfluxDB            `yaml:"influxdb"`
	LokiClient          LoggerLokiClient          `yaml:"lokiclient"`
	Statsd              LoggerStatsd              `yaml:"statsd"`
	Nsq                 LoggerNsq                 `yaml:"nsq"`
	ElasticSearchClient LoggerElasticSearchClient `yaml:"elasticsearch"`
	OpenTelemetryClient LoggerOpenTelemetryClient `yaml:"opentelemetry"`
	ScalyrClient        LoggerScalyrClient        `yaml:"scalyrclient"`
	RedisPub            LoggerRedisPub            `yaml:"redispub"`
	KafkaProducer       LoggerKafkaProducer       `yaml:"kafkaproducer"`
	FalcoClient         LoggerFalcoClient         `yaml:"falco"`
	ClickhouseClient    LoggerClickhouseClient    `yaml:"clickhouse"`
	MQTT                LoggerMQTT                `yaml:"mqtt"`
	TopN                LoggerTopN                `yaml:"topn"`
	Webhook             LoggerWebhook             `yaml:"webhook"`
}

type LoggerWebhook struct {
	Enable           bool   `yaml:"enable" default:"false"`
	URL              string `yaml:"url" default:"http://127.0.0.1:8088"`
	Timeout          int    `yaml:"timeout" default:"1"`
	BasicAuthEnabled bool   `yaml:"basic-auth-enable" default:"false"`
	BasicAuthLogin   string `yaml:"basic-auth-login" default:""`
	BasicAuthPwd     string `yaml:"basic-auth-pwd" default:""`
	NumThreads       int    `yaml:"num-threads" default:"1"`
}

type LoggerTopN struct {
	Enable       bool   `yaml:"enable" default:"false"`
	Interval     int    `yaml:"interval" default:"60"`
	TopN         int    `yaml:"top-n" default:"10"`
	Mode         string `yaml:"mode" default:"text"`
	Output       string `yaml:"output" default:"stdout"`
	FilePath     string `yaml:"file-path" default:""`
	TrackQnames  bool   `yaml:"track-qnames" default:"true"`
	TrackClients bool   `yaml:"track-clients" default:"true"`
	TrackRcodes  bool   `yaml:"track-rcodes" default:"true"`
	TrackTlds    bool   `yaml:"track-tlds" default:"false"`
}

func (c *ConfigLoggers) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigLoggers) IsValid(userCfg map[string]interface{}) error {
	return CheckConfigWithTags(reflect.ValueOf(*c), userCfg)
}

func (c *ConfigLoggers) GetNames() (ret []string) {
	cl := reflect.TypeOf(*c)

	for i := 0; i < cl.NumField(); i++ {
		field := cl.Field(i)
		tag := field.Tag.Get("yaml")
		ret = append(ret, tag)
	}
	return ret
}

func (c *ConfigLoggers) IsExists(name string) bool {
	tags := c.GetNames()
	for i := range tags {
		if name == tags[i] {
			return true
		}
	}
	return false
}
