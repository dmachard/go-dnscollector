package transformers

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

var (
	RETURN_SUCCESS = 1
	RETURN_DROP    = 2
	RETURN_ERROR   = 3
)

type Transforms struct {
	config   *dnsutils.ConfigTransformers
	logger   *logger.Logger
	name     string
	instance int

	SuspiciousTransform      SuspiciousTransform
	GeoipTransform           GeoIpProcessor
	FilteringTransform       FilteringProcessor
	UserPrivacyTransform     UserPrivacyProcessor
	NormalizeTransform       NormalizeProcessor
	LatencyTransform         *LatencyProcessor
	ReducerTransform         *ReducerProcessor
	ExtractProcessor         ExtractProcessor
	MachineLearningTransform MlProcessor

	activeTransforms []func(dm *dnsutils.DnsMessage) int
}

func NewTransforms(config *dnsutils.ConfigTransformers, logger *logger.Logger, name string, outChannels []chan dnsutils.DnsMessage, instance int) Transforms {

	d := Transforms{
		config:   config,
		logger:   logger,
		name:     name,
		instance: instance,
	}

	d.SuspiciousTransform = NewSuspiciousSubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.NormalizeTransform = NewNormalizeSubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.ExtractProcessor = NewExtractSubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.LatencyTransform = NewLatencySubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.ReducerTransform = NewReducerSubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.UserPrivacyTransform = NewUserPrivacySubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.FilteringTransform = NewFilteringProcessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.GeoipTransform = NewDnsGeoIpProcessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.MachineLearningTransform = NewMachineLearningSubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)

	d.Prepare()
	return d
}

func (p *Transforms) ReloadConfig(config *dnsutils.ConfigTransformers) {
	p.config = config
	p.NormalizeTransform.ReloadConfig(config)
	p.GeoipTransform.ReloadConfig(config)
	p.FilteringTransform.ReloadConfig(config)
	p.UserPrivacyTransform.ReloadConfig(config)
	p.LatencyTransform.ReloadConfig(config)
	p.SuspiciousTransform.ReloadConfig(config)
	p.ReducerTransform.ReloadConfig(config)

	p.Prepare()
}

func (p *Transforms) Prepare() error {
	// clean the slice
	p.activeTransforms = p.activeTransforms[:0]

	if p.config.Normalize.Enable {
		prefixlog := fmt.Sprintf("transformer=normalize#%d ", p.instance)
		p.LogInfo(prefixlog + "enabled")

		p.NormalizeTransform.LoadActiveProcessors()
	}

	if p.config.GeoIP.Enable {
		p.activeTransforms = append(p.activeTransforms, p.geoipTransform)
		prefixlog := fmt.Sprintf("transformer=geoip#%d ", p.instance)
		p.LogInfo(prefixlog + "enabled")

		if err := p.GeoipTransform.Open(); err != nil {
			p.LogError(prefixlog+"open error %v", err)
		}
	}

	if p.config.UserPrivacy.Enable {
		// Apply user privacy on qname and query ip
		if p.config.UserPrivacy.AnonymizeIP {
			p.activeTransforms = append(p.activeTransforms, p.anonymizeIP)
			prefixlog := fmt.Sprintf("transformer=userprivacy#%d - ", p.instance)
			p.LogInfo(prefixlog + "subprocessor anonymizeIP is enabled")
		}

		if p.config.UserPrivacy.MinimazeQname {
			p.activeTransforms = append(p.activeTransforms, p.minimazeQname)
			prefixlog := fmt.Sprintf("transformer=userprivacy#%d - ", p.instance)
			p.LogInfo(prefixlog + "subprocessor minimaze qnam is  enabled")
		}

		if p.config.UserPrivacy.HashIP {
			p.activeTransforms = append(p.activeTransforms, p.hashIP)
			prefixlog := fmt.Sprintf("transformer=userprivacy#%d - ", p.instance)
			p.LogInfo(prefixlog + "subprocessor hashIP is enabled")
		}
	}

	if p.config.Filtering.Enable {
		prefixlog := fmt.Sprintf("transformer=filtering#%d ", p.instance)
		p.LogInfo(prefixlog + "enabled")

		p.FilteringTransform.LoadRcodes()
		p.FilteringTransform.LoadDomainsList()
		p.FilteringTransform.LoadQueryIpList()
		p.FilteringTransform.LoadrDataIpList()

		p.FilteringTransform.LoadActiveFilters()
	}

	if p.config.Latency.Enable {
		if p.config.Latency.MeasureLatency {
			p.activeTransforms = append(p.activeTransforms, p.measureLatency)
			prefixlog := fmt.Sprintf("transformer=latency#%d - ", p.instance)
			p.LogInfo(prefixlog + "subprocessor measure latency is enabled")
		}
		if p.config.Latency.UnansweredQueries {
			p.activeTransforms = append(p.activeTransforms, p.detectEvictedTimeout)
			prefixlog := fmt.Sprintf("transformer=latency#%d - ", p.instance)
			p.LogInfo(prefixlog + "subprocessor unanswered queries is enabled")
		}
	}

	if p.config.Suspicious.Enable {
		p.activeTransforms = append(p.activeTransforms, p.suspiciousTransform)
		prefixlog := fmt.Sprintf("transformer=suspicious#%d - ", p.instance)
		p.LogInfo(prefixlog + "is enabled")
	}

	if p.config.Reducer.Enable {
		prefixlog := fmt.Sprintf("transformer=reducer#%d - ", p.instance)
		p.LogInfo(prefixlog + "is enabled")

		p.ReducerTransform.LoadActiveReducers()
	}

	if p.config.Extract.Enable {
		if p.config.Extract.AddPayload {
			p.activeTransforms = append(p.activeTransforms, p.addBase64Payload)
			prefixlog := fmt.Sprintf("transformer=extract#%d - ", p.instance)
			p.LogInfo(prefixlog + "subprocessor add base64 payload is enabled")
		}
	}

	if p.config.MachineLearning.Enable {
		p.activeTransforms = append(p.activeTransforms, p.machineLearningTransform)
		prefixlog := fmt.Sprintf("transformer=ml#%d - ", p.instance)
		p.LogInfo(prefixlog + "is enabled")
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
	if p.config.Reducer.Enable {
		p.ReducerTransform.InitDnsMessage(dm)
	}
	if p.config.MachineLearning.Enable {
		p.MachineLearningTransform.InitDnsMessage(dm)
	}
}

func (p *Transforms) Reset() {
	if p.config.GeoIP.Enable {
		p.GeoipTransform.Close()
	}
}

func (p *Transforms) LogInfo(msg string, v ...interface{}) {
	p.logger.Info("["+p.name+"] "+msg, v...)
}

func (p *Transforms) LogError(msg string, v ...interface{}) {
	p.logger.Error("["+p.name+"] "+msg, v...)
}

// transform functions: return code
func (p *Transforms) machineLearningTransform(dm *dnsutils.DnsMessage) int {
	p.MachineLearningTransform.AddFeatures(dm)
	return RETURN_SUCCESS
}

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

func (p *Transforms) addBase64Payload(dm *dnsutils.DnsMessage) int {
	dm.Extracted.Base64Payload = p.ExtractProcessor.AddBase64Payload(dm)
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
