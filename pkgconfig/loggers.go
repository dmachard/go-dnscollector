package pkgconfig

import (
	"reflect"

	"github.com/creasty/defaults"
	"github.com/prometheus/prometheus/model/relabel"
)

type ConfigLoggers struct {
	DevNull struct {
		Enable            bool `yaml:"enable" default:"false"`
		ChannelBufferSize int  `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"devnull"`
	Stdout struct {
		Enable            bool   `yaml:"enable" default:"false"`
		Mode              string `yaml:"mode" default:"text"`
		TextFormat        string `yaml:"text-format" default:""`
		JinjaFormat       string `yaml:"jinja-format" default:""`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"stdout"`
	Prometheus struct {
		Enable                    bool     `yaml:"enable" default:"false"`
		ListenIP                  string   `yaml:"listen-ip" default:"127.0.0.1"`
		ListenPort                int      `yaml:"listen-port" default:"8081"`
		TLSSupport                bool     `yaml:"tls-support" default:"false"`
		TLSMutual                 bool     `yaml:"tls-mutual" default:"false"`
		TLSMinVersion             string   `yaml:"tls-min-version" default:"1.2"`
		CertFile                  string   `yaml:"cert-file" default:""`
		KeyFile                   string   `yaml:"key-file" default:""`
		PromPrefix                string   `yaml:"prometheus-prefix" default:"dnscollector"`
		LabelsList                []string `yaml:"prometheus-labels" default:"[]"`
		TopN                      int      `yaml:"top-n" default:"10"`
		BasicAuthLogin            string   `yaml:"basic-auth-login" default:"admin"`
		BasicAuthPwd              string   `yaml:"basic-auth-pwd" default:"changeme"`
		BasicAuthEnabled          bool     `yaml:"basic-auth-enable" default:"true"`
		ChannelBufferSize         int      `yaml:"chan-buffer-size" default:"0"`
		RequestersMetricsEnabled  bool     `yaml:"requesters-metrics-enabled" default:"true"`
		DomainsMetricsEnabled     bool     `yaml:"domains-metrics-enabled" default:"true"`
		NoErrorMetricsEnabled     bool     `yaml:"noerror-metrics-enabled" default:"true"`
		ServfailMetricsEnabled    bool     `yaml:"servfail-metrics-enabled" default:"true"`
		NonExistentMetricsEnabled bool     `yaml:"nonexistent-metrics-enabled" default:"true"`
		TimeoutMetricsEnabled     bool     `yaml:"timeout-metrics-enabled" default:"false"`
		HistogramMetricsEnabled   bool     `yaml:"histogram-metrics-enabled" default:"false"`
		RequestersCacheTTL        int      `yaml:"requesters-cache-ttl" default:"250000"`
		RequestersCacheSize       int      `yaml:"requesters-cache-size" default:"3600"`
		DomainsCacheTTL           int      `yaml:"domains-cache-ttl" default:"500000"`
		DomainsCacheSize          int      `yaml:"domains-cache-size" default:"3600"`
		NoErrorDomainsCacheTTL    int      `yaml:"noerror-domains-cache-ttl" default:"100000"`
		NoErrorDomainsCacheSize   int      `yaml:"noerror-domains-cache-size" default:"3600"`
		ServfailDomainsCacheTTL   int      `yaml:"servfail-domains-cache-ttl" default:"10000"`
		ServfailDomainsCacheSize  int      `yaml:"servfail-domains-cache-size" default:"3600"`
		NXDomainsCacheTTL         int      `yaml:"nonexistent-domains-cache-ttl" default:"10000"`
		NXDomainsCacheSize        int      `yaml:"nonexistent-domains-cache-size" default:"3600"`
		DefaultDomainsCacheTTL    int      `yaml:"default-domains-cache-ttl" default:"1000"`
		DefaultDomainsCacheSize   int      `yaml:"default-domains-cache-size" default:"3600"`
	} `yaml:"prometheus"`
	RestAPI struct {
		Enable            bool   `yaml:"enable" default:"false"`
		ListenIP          string `yaml:"listen-ip" default:"127.0.0.1"`
		ListenPort        int    `yaml:"listen-port" default:"8080"`
		BasicAuthLogin    string `yaml:"basic-auth-login" default:"admin"`
		BasicAuthPwd      string `yaml:"basic-auth-pwd" default:"changeme"`
		TLSSupport        bool   `yaml:"tls-support" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		TopN              int    `yaml:"top-n" default:"100"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"restapi"`
	LogFile struct {
		Enable            bool   `yaml:"enable" default:"false"`
		FilePath          string `yaml:"file-path" default:""`
		MaxSize           int    `yaml:"max-size" default:"100"`
		MaxFiles          int    `yaml:"max-files" default:"10"`
		MaxBatchSize      int    `yaml:"max-batch-size" default:"65536"`
		FlushInterval     int    `yaml:"flush-interval" default:"1"`
		Compress          bool   `yaml:"compress" default:"false"`
		Mode              string `yaml:"mode" default:"text"`
		PostRotateCommand string `yaml:"postrotate-command" default:""`
		PostRotateDelete  bool   `yaml:"postrotate-delete-success" default:"false"`
		TextFormat        string `yaml:"text-format" default:""`
		JinjaFormat       string `yaml:"jinja-format" default:""`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
		ExtendedSupport   bool   `yaml:"extended-support" default:"false"`
	} `yaml:"logfile"`
	DNSTap struct {
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
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
		ExtendedSupport   bool   `yaml:"extended-support" default:"false"`
		Compression       string `yaml:"compression" default:"none"`
	} `yaml:"dnstapclient"`
	TCPClient struct {
		Enable            bool   `yaml:"enable" default:"false"`
		RemoteAddress     string `yaml:"remote-address" default:"127.0.0.1"`
		RemotePort        int    `yaml:"remote-port" default:"9999"`
		SockPath          string `yaml:"sock-path" default:""` // deprecated
		RetryInterval     int    `yaml:"retry-interval" default:"10"`
		Transport         string `yaml:"transport" default:"tcp"`
		TLSSupport        bool   `yaml:"tls-support" default:"false"` // deprecated
		TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CAFile            string `yaml:"ca-file" default:""`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		Mode              string `yaml:"mode" default:"flat-json"`
		TextFormat        string `yaml:"text-format" default:""`
		PayloadDelimiter  string `yaml:"delimiter" default:"\n"`
		BufferSize        int    `yaml:"buffer-size" default:"100"`
		FlushInterval     int    `yaml:"flush-interval" default:"30"`
		ConnectTimeout    int    `yaml:"connect-timeout" default:"5"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"tcpclient"`
	Syslog struct {
		Enable            bool   `yaml:"enable" default:"false"`
		Severity          string `yaml:"severity" default:"INFO"`
		Facility          string `yaml:"facility" default:"DAEMON"`
		Transport         string `yaml:"transport" default:"local"`
		RemoteAddress     string `yaml:"remote-address" default:"127.0.0.1:514"`
		RetryInterval     int    `yaml:"retry-interval" default:"10"`
		TextFormat        string `yaml:"text-format" default:""`
		Mode              string `yaml:"mode" default:"text"`
		TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CAFile            string `yaml:"ca-file" default:""`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		Formatter         string `yaml:"formatter" default:"rfc5424"`
		Framer            string `yaml:"framer" default:""`
		Hostname          string `yaml:"hostname" default:""`
		AppName           string `yaml:"app-name" default:"DNScollector"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
		Tag               string `yaml:"tag" default:""`
		ReplaceNullChar   string `yaml:"replace-null-char" default:"�"`
		FlushInterval     int    `yaml:"flush-interval" default:"30"`
		BufferSize        int    `yaml:"buffer-size" default:"100"`
	} `yaml:"syslog"`
	Fluentd struct {
		Enable            bool   `yaml:"enable" default:"false"`
		RemoteAddress     string `yaml:"remote-address" default:"127.0.0.1"`
		RemotePort        int    `yaml:"remote-port" default:"24224"`
		SockPath          string `yaml:"sock-path" default:""` // deprecated
		ConnectTimeout    int    `yaml:"connect-timeout" default:"5"`
		RetryInterval     int    `yaml:"retry-interval" default:"10"`
		FlushInterval     int    `yaml:"flush-interval" default:"30"`
		Transport         string `yaml:"transport" default:"tcp"`
		TLSSupport        bool   `yaml:"tls-support" default:"false"` // deprecated
		TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CAFile            string `yaml:"ca-file" default:""`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		Tag               string `yaml:"tag" default:"dns.collector"`
		BufferSize        int    `yaml:"buffer-size" default:"100"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"4096"`
	} `yaml:"fluentd"`
	InfluxDB struct {
		Enable            bool   `yaml:"enable" default:"false"`
		ServerURL         string `yaml:"server-url" default:"http://localhost:8086"`
		AuthToken         string `yaml:"auth-token" default:""`
		TLSSupport        bool   `yaml:"tls-support" default:"false"`
		TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CAFile            string `yaml:"ca-file" default:""`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		Bucket            string `yaml:"bucket" default:""`
		Organization      string `yaml:"organization" default:""`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"influxdb"`
	LokiClient struct {
		Enable            bool              `yaml:"enable" default:"false"`
		ServerURL         string            `yaml:"server-url" default:"http://localhost:3100/loki/api/v1/push"`
		JobName           string            `yaml:"job-name" default:"dnscollector"`
		Mode              string            `yaml:"mode" default:"text"`
		FlushInterval     int               `yaml:"flush-interval" default:"5"`
		BatchSize         int               `yaml:"batch-size" default:"1048576"`
		RetryInterval     int               `yaml:"retry-interval" default:"10"`
		TextFormat        string            `yaml:"text-format" default:""`
		ProxyURL          string            `yaml:"proxy-url" default:""`
		TLSInsecure       bool              `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string            `yaml:"tls-min-version" default:"1.2"`
		CAFile            string            `yaml:"ca-file" default:""`
		CertFile          string            `yaml:"cert-file" default:""`
		KeyFile           string            `yaml:"key-file" default:""`
		BasicAuthLogin    string            `yaml:"basic-auth-login" default:""`
		BasicAuthPwd      string            `yaml:"basic-auth-pwd" default:""`
		BasicAuthPwdFile  string            `yaml:"basic-auth-pwd-file" default:""`
		TenantID          string            `yaml:"tenant-id" default:""`
		RelabelConfigs    []*relabel.Config `yaml:"relabel-configs" default:"[]"`
		ChannelBufferSize int               `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"lokiclient"`
	Statsd struct {
		Enable            bool   `yaml:"enable" default:"false"`
		Prefix            string `yaml:"prefix" default:"dnscollector"`
		RemoteAddress     string `yaml:"remote-address" default:"127.0.0.1"`
		RemotePort        int    `yaml:"remote-port" default:"8125"`
		ConnectTimeout    int    `yaml:"connect-timeout" default:"5"`
		Transport         string `yaml:"transport" default:"udp"`
		FlushInterval     int    `yaml:"flush-interval" default:"10"`
		CertFile          string `yaml:"cert-file" default:""`
		TLSSupport        bool   `yaml:"tls-support" default:"false"` // deprecated
		TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CAFile            string `yaml:"ca-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"statsd"`
	ElasticSearchClient struct {
		Enable            bool   `yaml:"enable" default:"false"`
		Index             string `yaml:"index" default:"dnscollector"`
		Server            string `yaml:"server" default:"http://127.0.0.1:9200/"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
		BulkSize          int    `yaml:"bulk-size" default:"5242880"`
		BulkChannelSize   int    `yaml:"bulk-channel-size" default:"10"`
		FlushInterval     int    `yaml:"flush-interval" default:"10"`
		Compression       string `yaml:"compression" default:"none"`
	} `yaml:"elasticsearch"`
	ScalyrClient struct {
		Enable            bool                   `yaml:"enable" default:"false"`
		Mode              string                 `yaml:"mode" default:"text"`
		TextFormat        string                 `yaml:"text-format" default:""`
		SessionInfo       map[string]string      `yaml:"sessioninfo" default:"{}"`
		Attrs             map[string]interface{} `yaml:"attrs" default:"{}"`
		ServerURL         string                 `yaml:"server-url" default:"app.scalyr.com"`
		APIKey            string                 `yaml:"apikey" default:""`
		Parser            string                 `yaml:"parser" default:""`
		FlushInterval     int                    `yaml:"flush-interval" default:"10"`
		ProxyURL          string                 `yaml:"proxy-url" default:""`
		TLSInsecure       bool                   `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string                 `yaml:"tls-min-version" default:"1.2"`
		CAFile            string                 `yaml:"ca-file" default:""`
		CertFile          string                 `yaml:"cert-file" default:""`
		KeyFile           string                 `yaml:"key-file" default:""`
		ChannelBufferSize int                    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"scalyrclient"`
	RedisPub struct {
		Enable            bool   `yaml:"enable" default:"false"`
		RemoteAddress     string `yaml:"remote-address" default:"127.0.0.1"`
		RemotePort        int    `yaml:"remote-port" default:"6379"`
		SockPath          string `yaml:"sock-path" default:""` // deprecated
		RetryInterval     int    `yaml:"retry-interval" default:"10"`
		Transport         string `yaml:"transport" default:"tcp"`
		TLSSupport        bool   `yaml:"tls-support" default:"false"` // deprecated
		TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CAFile            string `yaml:"ca-file" default:""`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		Mode              string `yaml:"mode" default:"flat-json"`
		TextFormat        string `yaml:"text-format" default:""`
		PayloadDelimiter  string `yaml:"delimiter" default:"\n"`
		BufferSize        int    `yaml:"buffer-size" default:"100"`
		FlushInterval     int    `yaml:"flush-interval" default:"30"`
		ConnectTimeout    int    `yaml:"connect-timeout" default:"5"`
		RedisChannel      string `yaml:"redis-channel" default:"dns_collector"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"redispub"`
	KafkaProducer struct {
		Enable            bool   `yaml:"enable" default:"false"`
		RemoteAddress     string `yaml:"remote-address" default:"127.0.0.1"`
		RemotePort        int    `yaml:"remote-port" default:"9092"`
		RetryInterval     int    `yaml:"retry-interval" default:"10"`
		TLSSupport        bool   `yaml:"tls-support" default:"false"`
		TLSInsecure       bool   `yaml:"tls-insecure" default:"false"`
		TLSMinVersion     string `yaml:"tls-min-version" default:"1.2"`
		CAFile            string `yaml:"ca-file" default:""`
		CertFile          string `yaml:"cert-file" default:""`
		KeyFile           string `yaml:"key-file" default:""`
		SaslSupport       bool   `yaml:"sasl-support" default:"false"`
		SaslUsername      string `yaml:"sasl-username" default:""`
		SaslPassword      string `yaml:"sasl-password" default:""`
		SaslMechanism     string `yaml:"sasl-mechanism" default:"PLAIN"`
		Mode              string `yaml:"mode" default:"flat-json"`
		TextFormat        string `yaml:"text-format" default:""`
		BufferSize        int    `yaml:"buffer-size" default:"100"`
		FlushInterval     int    `yaml:"flush-interval" default:"10"`
		ConnectTimeout    int    `yaml:"connect-timeout" default:"5"`
		Topic             string `yaml:"topic" default:"dnscollector"`
		Partition         *int   `yaml:"partition" default:"nil"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
		Compression       string `yaml:"compression" default:"none"`
	} `yaml:"kafkaproducer"`
	FalcoClient struct {
		Enable            bool   `yaml:"enable" default:"false"`
		URL               string `yaml:"url" default:"http://127.0.0.1:9200"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"falco"`
	ClickhouseClient struct {
		Enable            bool   `yaml:"enable" default:"false"`
		URL               string `yaml:"url" default:"http://localhost:8123"`
		User              string `yaml:"user" default:"default"`
		Password          string `yaml:"password" default:"password"`
		Database          string `yaml:"database" default:"dnscollector"`
		Table             string `yaml:"table" default:"records"`
		ChannelBufferSize int    `yaml:"chan-buffer-size" default:"0"`
	} `yaml:"clickhouse"`
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
