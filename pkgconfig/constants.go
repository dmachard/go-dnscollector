package pkgconfig

const (
	StrUnknown = "UNKNOWN"

	ProgQname   = "dns.collector"
	ProgName    = "dnscollector"
	LocalhostIP = "127.0.0.1"
	AnyIP       = "0.0.0.0"
	HTTPOK      = "HTTP/1.1 200 OK\r\n\r\n"

	KeyCollectors = "collectors"
	KeyLoggers    = "loggers"

	ValidDomain       = "dnscollector.dev."
	BadDomainLabel    = "ultramegaverytoolonglabel-ultramegaverytoolonglabel-ultramegaverytoolonglabel.dnscollector.dev."
	badLongLabel      = "ultramegaverytoolonglabel-ultramegaverytoolonglabel-"
	BadVeryLongDomain = "ultramegaverytoolonglabel.dnscollector" + badLongLabel + badLongLabel +
		badLongLabel + badLongLabel + badLongLabel + ".dev."

	ModeText     = "text"
	ModeJSON     = "json"
	ModeFlatJSON = "flat-json"
	ModePCAP     = "pcap"
	ModeDNSTap   = "dnstap"

	SASLMechanismPlain = "PLAIN"
	SASLMechanismScram = "SCRAM-SHA-512"

	CompressGzip   = "gzip"
	CompressSnappy = "snappy"
	CompressLz4    = "lz4"
	CompressZstd   = "ztd"
	CompressNone   = "none"
)

var (
	PrefixLogWorker       = "worker - "
	PrefixLogTransformer  = "transformer - "
	DefaultBufferSize     = 512
	DefaultBufferOne      = 1
	DefaultMonitor        = true
	WorkerMonitorDisabled = false

	ExpectedQname         = "dnscollector.dev"
	ExpectedQname2        = "dns.collector"
	ExpectedBufferMsg511  = ".*buffer is full, 511.*"
	ExpectedBufferMsg1023 = ".*buffer is full, 1023.*"
	ExpectedIdentity      = "powerdnspb"
)
