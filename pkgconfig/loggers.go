package pkgconfig

import "github.com/prometheus/prometheus/model/relabel"

type ConfigLoggers struct {
	Stdout struct {
		Enable            bool   `yaml:"enable"`
		Mode              string `yaml:"mode"`
		TextFormat        string `yaml:"text-format"`
		ChannelBufferSize int    `yaml:"chan-buffer-size"`
	} `yaml:"stdout"`
	Prometheus struct {
		Enable                  bool     `yaml:"enable"`
		ListenIP                string   `yaml:"listen-ip"`
		ListenPort              int      `yaml:"listen-port"`
		TLSSupport              bool     `yaml:"tls-support"`
		TLSMutual               bool     `yaml:"tls-mutual"`
		TLSMinVersion           string   `yaml:"tls-min-version"`
		CertFile                string   `yaml:"cert-file"`
		KeyFile                 string   `yaml:"key-file"`
		PromPrefix              string   `yaml:"prometheus-prefix"`
		LabelsList              []string `yaml:"prometheus-labels"`
		TopN                    int      `yaml:"top-n"`
		BasicAuthLogin          string   `yaml:"basic-auth-login"`
		BasicAuthPwd            string   `yaml:"basic-auth-pwd"`
		BasicAuthEnabled        bool     `yaml:"basic-auth-enable"`
		ChannelBufferSize       int      `yaml:"chan-buffer-size"`
		HistogramMetricsEnabled bool     `yaml:"histogram-metrics-enabled"`
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
	} `yaml:"dnstap"`
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
