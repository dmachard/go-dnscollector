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
	LatencyTransform     *LatencyProcessor
	ReducerTransform     *ReducerProcessor
	ExtractProcessor     ExtractProcessor

	activeTransforms []func(dm *dnsutils.DnsMessage) int
}

func NewTransforms(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string, outChannels []chan dnsutils.DnsMessage) Transforms {

	d := Transforms{
		config: config,
		logger: logger,
		name:   name,

		SuspiciousTransform:  NewSuspiciousSubprocessor(config, logger, name),
		GeoipTransform:       NewDnsGeoIpProcessor(config, logger),
		FilteringTransform:   NewFilteringProcessor(config, logger, name),
		UserPrivacyTransform: NewUserPrivacySubprocessor(config),
		NormalizeTransform:   NewNormalizeSubprocessor(config, logger, name),
		LatencyTransform:     NewLatencySubprocessor(config, logger, name, outChannels),
		ReducerTransform:     NewReducerSubprocessor(config, logger, name, outChannels),
		ExtractProcessor:     NewExtractSubprocessor(config),
	}

	d.Prepare()
	return d
}

func (p *Transforms) Prepare() error {

	if p.config.GeoIP.Enable {
		p.activeTransforms = append(p.activeTransforms, p.geoipTransform)
		p.LogInfo("[GeoIP] enabled")

		if err := p.GeoipTransform.Open(); err != nil {
			p.LogError("geoip open error %v", err)
		}
	}

	if p.config.UserPrivacy.Enable {
		// Apply user privacy on qname and query ip
		if p.config.UserPrivacy.AnonymizeIP {
			p.activeTransforms = append(p.activeTransforms, p.anonymizeIP)
			p.LogInfo("[user privacy: anonymize IP] enabled")
		}

		if p.config.UserPrivacy.MinimazeQname {
			p.activeTransforms = append(p.activeTransforms, p.minimazeQname)
			p.LogInfo("[user privacy: minimaze Qname] enabled")
		}

		if p.config.UserPrivacy.HashIP {
			p.activeTransforms = append(p.activeTransforms, p.hashIP)
			p.LogInfo("[user privacy: hash IP] enabled")
		}
	}

	if p.config.Suspicious.Enable {
		p.activeTransforms = append(p.activeTransforms, p.suspiciousTransform)
		p.LogInfo("[suspicious] enabled")
	}

	if p.config.Filtering.Enable {
		p.LogInfo("[filtering] enabled")
	}

	if p.config.Latency.Enable {
		if p.config.Latency.MeasureLatency {
			p.activeTransforms = append(p.activeTransforms, p.measureLatency)
			p.LogInfo("[latency: measure latency] enabled")
		}
		if p.config.Latency.UnansweredQueries {
			p.activeTransforms = append(p.activeTransforms, p.detectEvictedTimeout)
			p.LogInfo("[latency: unanswered queries] enabled")
		}
	}

	if p.config.Reducer.Enable {
		p.LogInfo("[reducer] enabled")
	}

	if p.config.Extract.Enable {
		if p.config.Extract.AddPayload {
			p.activeTransforms = append(p.activeTransforms, p.addBase64Payload)
			p.LogInfo("[extract: payload] enabled")
		}

	}

	return nil
}

func (p *Transforms) InitDnsMessageFormat(dm *dnsutils.DnsMessage) {
	if p.config.GeoIP.Enable {
		p.GeoipTransform.InitDnsMessage(dm)
	}
	if p.config.Suspicious.Enable {
		p.SuspiciousTransform.InitDnsMessage(dm)
	}
	if p.config.Normalize.Enable {
		if p.config.Normalize.AddTld || p.config.Normalize.AddTldPlusOne {
			p.NormalizeTransform.InitDnsMessage(dm)
		}
	}
	if p.config.Extract.Enable {
		if p.config.Extract.AddPayload {
			p.ExtractProcessor.InitDnsMessage(dm)
		}
	}
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
	dm.Geo.AutonomousSystemNumber = geoInfo.ASN
	dm.Geo.AutonomousSystemOrg = geoInfo.ASO

	return RETURN_SUCCESS
}

func (p *Transforms) anonymizeIP(dm *dnsutils.DnsMessage) int {
	dm.NetworkInfo.QueryIp = p.UserPrivacyTransform.AnonymizeIP(dm.NetworkInfo.QueryIp)

	return RETURN_SUCCESS
}

func (p *Transforms) hashIP(dm *dnsutils.DnsMessage) int {
	dm.NetworkInfo.QueryIp = p.UserPrivacyTransform.HashIP(dm.NetworkInfo.QueryIp)
	dm.NetworkInfo.ResponseIp = p.UserPrivacyTransform.HashIP(dm.NetworkInfo.ResponseIp)
	return RETURN_SUCCESS
}

func (p *Transforms) measureLatency(dm *dnsutils.DnsMessage) int {
	p.LatencyTransform.MeasureLatency(dm)
	return RETURN_SUCCESS
}

func (p *Transforms) detectEvictedTimeout(dm *dnsutils.DnsMessage) int {
	p.LatencyTransform.DetectEvictedTimeout(dm)
	return RETURN_SUCCESS
}

func (p *Transforms) minimazeQname(dm *dnsutils.DnsMessage) int {
	dm.DNS.Qname = p.UserPrivacyTransform.MinimazeQname(dm.DNS.Qname)

	return RETURN_SUCCESS
}

func (p *Transforms) ProcessMessage(dm *dnsutils.DnsMessage) int {
	// Begin to normalize
	p.NormalizeTransform.ProcessDnsMessage(dm)

	// Traffic filtering ?
	if p.FilteringTransform.CheckIfDrop(dm) {
		return RETURN_DROP
	}

	// Traffic reducer ?
	if p.ReducerTransform.ProcessDnsMessage(dm) == RETURN_DROP {
		return RETURN_DROP
	}

	//  and finaly apply other transformation
	var r_code int
	for _, fn := range p.activeTransforms {
		r_code = fn(dm)
		if r_code != RETURN_SUCCESS {
			return r_code
		}
	}

	return RETURN_SUCCESS
}

func (p *Transforms) addBase64Payload(dm *dnsutils.DnsMessage) int {
	dm.Extracted.Base64Payload = p.ExtractProcessor.AddBase64Payload(dm)
	return RETURN_SUCCESS
}
