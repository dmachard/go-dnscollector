package transformers

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

var (
	RETURN_SUCCESS = 1
	RETURN_DROP    = 2
	RETURN_ERROR   = 3
)

type Transforms struct {
	config *dnsutils.ConfigTransformers
	logger *logger.Logger
	name   string

	SuspiciousTransform  SuspiciousTransform
	GeoipTransform       GeoIpProcessor
	FilteringTransform   FilteringProcessor
	UserPrivacyTransform UserPrivacyProcessor
	NormalizeTransform   NormalizeProcessor
}

func NewTransforms(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string) Transforms {

	d := Transforms{
		config: config,
		logger: logger,
		name:   name,

		SuspiciousTransform:  NewSuspiciousSubprocessor(config, logger, name),
		GeoipTransform:       NewDnsGeoIpProcessor(config, logger),
		FilteringTransform:   NewFilteringProcessor(config, logger, name),
		UserPrivacyTransform: NewUserPrivacySubprocessor(config),
		NormalizeTransform:   NewNormalizeSubprocessor(config),
	}

	d.Prepare()
	return d
}

func (p *Transforms) Prepare() error {
	if p.config.Normalize.Enable {
		p.LogInfo("[normalize] enabled")
	}

	if p.config.GeoIP.Enable {
		p.LogInfo("[GeoIP] enabled")
		if err := p.GeoipTransform.Open(); err != nil {
			p.LogError("geoip open error %v", err)
		}
	}

	if p.config.UserPrivacy.Enable {
		p.LogInfo("[user privacy] enabled")
	}

	if p.config.Filtering.Enable {
		p.LogInfo("[filtering] enabled")
	}

	if p.config.Suspicious.Enable {
		p.LogInfo("[suspicious] enabled")
	}
	return nil
}

func (p *Transforms) Reset() {
	if p.config.GeoIP.Enable {
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
	if p.config.Normalize.Enable {
		if p.config.Normalize.QnameLowerCase {
			dm.DNS.Qname = p.NormalizeTransform.Lowercase(dm.DNS.Qname)
		}
	}

	// Traffic filtering ?
	if p.config.Filtering.Enable {
		if p.FilteringTransform.CheckIfDrop(dm) {
			return RETURN_DROP
		}
	}

	// Apply user privacy on qname and query ip
	if p.config.UserPrivacy.Enable {
		if p.config.UserPrivacy.AnonymizeIP {
			dm.NetworkInfo.QueryIp = p.UserPrivacyTransform.AnonymizeIP(dm.NetworkInfo.QueryIp)
		}
		if p.config.UserPrivacy.MinimazeQname {
			dm.DNS.Qname = p.UserPrivacyTransform.MinimazeQname(dm.DNS.Qname)
		}
	}

	// Add GeoIP metadata ?
	if p.config.GeoIP.Enable {
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
	if p.config.Suspicious.Enable {
		p.SuspiciousTransform.CheckIfSuspicious(dm)
	}

	return RETURN_SUCCESS
}
