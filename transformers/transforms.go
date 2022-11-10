package transformers

import (
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

var (
	RETURN_SUCCESS = 1
	RETURN_DROP    = 2
	RETURN_ERROR   = 3
)

type Transforms struct {
	config *dnsutils.Config
	logger *logger.Logger
	name   string

	SuspiciousTransform   SuspiciousTransform
	GeoipTransform        GeoIpProcessor
	FilteringTransform    FilteringProcessor
	IpAnonymizerTransform IpAnonymizerSubproc
	QnameReducerTransform QnameReducer
}

func NewTransforms(config *dnsutils.Config, logger *logger.Logger, name string) Transforms {

	d := Transforms{
		config: config,
		logger: logger,
		name:   name,

		SuspiciousTransform:   NewSuspiciousSubprocessor(config, logger, name),
		GeoipTransform:        NewDnsGeoIpProcessor(config, logger),
		FilteringTransform:    NewFilteringProcessor(config, logger, name),
		IpAnonymizerTransform: NewIpAnonymizerSubprocessor(config),
		QnameReducerTransform: NewQnameReducerSubprocessor(config),
	}

	d.Prepare()
	return d
}

func (p *Transforms) Prepare() error {
	if p.config.Transformers.Normalize.Enable {
		p.LogInfo("normalize enabled")
	}

	if p.config.Transformers.GeoIP.Enable {
		p.LogInfo("GeoIP enabled")
		if err := p.GeoipTransform.Open(); err != nil {
			p.LogError("geoip open error %v", err)
		}
	}

	if p.config.Transformers.UserPrivacy.Enable {
		p.LogInfo("user privacy enabled")
	}

	if p.config.Transformers.Filtering.Enable {
		p.LogInfo("filtering enabled")
	}

	if p.config.Transformers.Suspicious.Enable {
		p.LogInfo("suspicious enabled")
	}
	return nil
}

func (p *Transforms) Reset() {
	if p.config.Transformers.GeoIP.Enable {
		p.GeoipTransform.Close()
	}
}

func (p *Transforms) LogInfo(msg string, v ...interface{}) {
	p.logger.Info("["+p.name+"] subprocessor - "+msg, v...)
}

func (p *Transforms) LogError(msg string, v ...interface{}) {
	p.logger.Error("["+p.name+"] subprocessor - "+msg, v...)
}

func (p *Transforms) ProcessMessage(dm *dnsutils.DnsMessage) int {

	// Normalize qname to lowercase
	if p.config.Transformers.Normalize.Enable {
		if p.config.Transformers.Normalize.QnameLowerCase {
			dm.DNS.Qname = strings.ToLower(dm.DNS.Qname)
		}
	}

	// Traffic filtering ?
	if p.config.Transformers.UserPrivacy.Enable {
		if p.FilteringTransform.CheckIfDrop(dm) {
			return RETURN_DROP
		}
	}

	// Apply user privacy on qname and query ip
	if p.config.Transformers.UserPrivacy.Enable {
		if p.config.Transformers.UserPrivacy.AnonymizeIP {
			dm.NetworkInfo.QueryIp = p.IpAnonymizerTransform.Anonymize(dm.NetworkInfo.QueryIp)
		}
		if p.config.Transformers.UserPrivacy.MinimazeQname {
			dm.DNS.Qname = p.QnameReducerTransform.Minimaze(dm.DNS.Qname)
		}
	}

	// Add GeoIP metadata ?
	if p.config.Transformers.GeoIP.Enable {
		geoInfo, err := p.GeoipTransform.Lookup(dm.NetworkInfo.QueryIp)
		if err != nil {
			p.LogError("geoip lookup error %v", err)
			return RETURN_ERROR
		}
		dm.Geo.Continent = geoInfo.Continent
		dm.Geo.CountryIsoCode = geoInfo.CountryISOCode
		dm.Geo.City = geoInfo.City
		dm.NetworkInfo.AutonomousSystemNumber = geoInfo.ASN
		dm.NetworkInfo.AutonomousSystemOrg = geoInfo.ASO
	}

	// add suspicious flags in DNS messages
	if p.config.Transformers.Suspicious.Enable {
		p.SuspiciousTransform.CheckIfSuspicious(dm)
	}

	return RETURN_SUCCESS
}
