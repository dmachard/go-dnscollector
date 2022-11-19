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

	SuspiciousTransform   SuspiciousTransform
	GeoipTransform        GeoIpProcessor
	FilteringTransform    FilteringProcessor
	UserPrivacyTransform  UserPrivacyProcessor
	NormalizeTransform    NormalizeProcessor
	PublicSuffixTransform PublicSuffixProcessor

	activeTransforms []func(dm *dnsutils.DnsMessage) int
}

func NewTransforms(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string) Transforms {

	d := Transforms{
		config: config,
		logger: logger,
		name:   name,

		SuspiciousTransform:   NewSuspiciousSubprocessor(config, logger, name),
		GeoipTransform:        NewDnsGeoIpProcessor(config, logger),
		FilteringTransform:    NewFilteringProcessor(config, logger, name),
		UserPrivacyTransform:  NewUserPrivacySubprocessor(config),
		NormalizeTransform:    NewNormalizeSubprocessor(config),
		PublicSuffixTransform: NewPublicSuffixSubprocessor(config),
	}

	d.Prepare()
	return d
}

func (p *Transforms) Prepare() error {
	if p.config.Normalize.Enable {
		if p.config.Normalize.QnameLowerCase {
			p.activeTransforms = append(p.activeTransforms, p.lowercaseQname)
			p.LogInfo("[normalize: lowercaseQname] enabled")
		}
		p.LogInfo("[normalize] enabled")
	}

	if p.config.GeoIP.Enable {
		p.activeTransforms = append(p.activeTransforms, p.geoipTransform)
		p.LogInfo("[GeoIP] enabled")

		if err := p.GeoipTransform.Open(); err != nil {
			p.LogError("geoip open error %v", err)
		}
	}

	if p.config.PublicSuffix.Enable {
		if p.config.PublicSuffix.AddTld {
			p.activeTransforms = append(p.activeTransforms, p.GetEffectiveTld)
			p.LogInfo("[public suffix: add tld] enabled")
		}
		if p.config.PublicSuffix.AddTldPlusOne {
			p.activeTransforms = append(p.activeTransforms, p.GetEffectiveTldPlusOne)
			p.LogInfo("[public suffix: add tld+1] enabled")
		}
	}

	if p.config.UserPrivacy.Enable {
		// Apply user privacy on qname and query ip
		if p.config.UserPrivacy.AnonymizeIP {
			p.activeTransforms = append(p.activeTransforms, p.anonymizeIP)
			p.LogInfo("[user privacy: anonymizeIP] enabled")
		}

		if p.config.UserPrivacy.MinimazeQname {
			p.activeTransforms = append(p.activeTransforms, p.minimazeQname)
			p.LogInfo("[user privacy: minimazeQname] enabled")
		}
	}

	if p.config.Suspicious.Enable {
		p.activeTransforms = append(p.activeTransforms, p.suspiciousTransform)
		p.LogInfo("[suspicious] enabled")
	}

	if p.config.Filtering.Enable {
		p.LogInfo("[filtering] enabled")
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

// transform functions: return code
func (p *Transforms) suspiciousTransform(dm *dnsutils.DnsMessage) int {
	p.SuspiciousTransform.CheckIfSuspicious(dm)
	return RETURN_SUCCESS
}

func (p *Transforms) geoipTransform(dm *dnsutils.DnsMessage) int {
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

	return RETURN_SUCCESS
}

func (p *Transforms) GetEffectiveTld(dm *dnsutils.DnsMessage) int {
	if etld, err := p.PublicSuffixTransform.GetEffectiveTld(dm.DNS.Qname); err == nil {
		dm.DNS.QnamePublicSuffix = etld
	}
	return RETURN_SUCCESS
}

func (p *Transforms) GetEffectiveTldPlusOne(dm *dnsutils.DnsMessage) int {
	if etld, err := p.PublicSuffixTransform.GetEffectiveTldPlusOne(dm.DNS.Qname); err == nil {
		dm.DNS.QnameEffectiveTLDPlusOne = etld
	}

	return RETURN_SUCCESS
}

func (p *Transforms) anonymizeIP(dm *dnsutils.DnsMessage) int {
	dm.NetworkInfo.QueryIp = p.UserPrivacyTransform.AnonymizeIP(dm.NetworkInfo.QueryIp)

	return RETURN_SUCCESS
}

func (p *Transforms) minimazeQname(dm *dnsutils.DnsMessage) int {
	dm.DNS.Qname = p.UserPrivacyTransform.MinimazeQname(dm.DNS.Qname)

	return RETURN_SUCCESS
}

func (p *Transforms) lowercaseQname(dm *dnsutils.DnsMessage) int {
	dm.DNS.Qname = p.NormalizeTransform.Lowercase(dm.DNS.Qname)

	return RETURN_SUCCESS
}

func (p *Transforms) ProcessMessage(dm *dnsutils.DnsMessage) int {
	// Traffic filtering ?
	if p.FilteringTransform.CheckIfDrop(dm) {
		return RETURN_DROP
	}

	// transform dm
	var r_code int
	for _, fn := range p.activeTransforms {
		r_code = fn(dm)
		if r_code != RETURN_SUCCESS {
			return r_code
		}
	}

	return RETURN_SUCCESS
}
