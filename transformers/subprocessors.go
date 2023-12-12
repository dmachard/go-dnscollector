package transformers

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

const (
	enabled = "enabled"
)

var (
	ReturnSuccess = 1
	ReturnDrop    = 2
	ReturnError   = 3
)

type Transforms struct {
	config   *pkgconfig.ConfigTransformers
	logger   *logger.Logger
	name     string
	instance int

	SuspiciousTransform      SuspiciousTransform
	GeoipTransform           GeoIPProcessor
	FilteringTransform       FilteringProcessor
	UserPrivacyTransform     UserPrivacyProcessor
	NormalizeTransform       NormalizeProcessor
	LatencyTransform         *LatencyProcessor
	ReducerTransform         *ReducerProcessor
	ExtractProcessor         ExtractProcessor
	MachineLearningTransform MlProcessor
	ATagsTransform           ATagsProcessor

	activeTransforms []func(dm *dnsutils.DNSMessage) int
}

func NewTransforms(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, outChannels []chan dnsutils.DNSMessage, instance int) Transforms {

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
	d.GeoipTransform = NewDNSGeoIPProcessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.MachineLearningTransform = NewMachineLearningSubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)
	d.ATagsTransform = NewATagsSubprocessor(config, logger, name, instance, outChannels, d.LogInfo, d.LogError)

	d.Prepare()
	return d
}

func (p *Transforms) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config
	p.NormalizeTransform.ReloadConfig(config)
	p.GeoipTransform.ReloadConfig(config)
	p.FilteringTransform.ReloadConfig(config)
	p.UserPrivacyTransform.ReloadConfig(config)
	p.LatencyTransform.ReloadConfig(config)
	p.SuspiciousTransform.ReloadConfig(config)
	p.ReducerTransform.ReloadConfig(config)
	p.ExtractProcessor.ReloadConfig(config)
	p.MachineLearningTransform.ReloadConfig(config)
	p.ATagsTransform.ReloadConfig(config)

	p.Prepare()
}

func (p *Transforms) Prepare() error {
	// clean the slice
	p.activeTransforms = p.activeTransforms[:0]

	if p.config.Normalize.Enable {
		prefixlog := fmt.Sprintf("transformer=normalize#%d ", p.instance)
		p.LogInfo(prefixlog + enabled)

		p.NormalizeTransform.LoadActiveProcessors()
	}

	if p.config.GeoIP.Enable {
		p.activeTransforms = append(p.activeTransforms, p.geoipTransform)
		prefixlog := fmt.Sprintf("transformer=geoip#%d ", p.instance)
		p.LogInfo(prefixlog + enabled)

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
		p.LogInfo(prefixlog + enabled)

		p.FilteringTransform.LoadRcodes()
		p.FilteringTransform.LoadDomainsList()
		p.FilteringTransform.LoadQueryIPList()
		p.FilteringTransform.LoadrDataIPList()

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
		p.LogInfo(prefixlog + enabled)
	}

	if p.config.Reducer.Enable {
		prefixlog := fmt.Sprintf("transformer=reducer#%d - ", p.instance)
		p.LogInfo(prefixlog + enabled)

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
		p.LogInfo(prefixlog + enabled)
	}

	if p.config.ATags.Enable {
		p.activeTransforms = append(p.activeTransforms, p.ATagsTransform.AddTags)
		prefixlog := fmt.Sprintf("transformer=atags#%d - ", p.instance)
		p.LogInfo(prefixlog + "subprocessor atags is enabled")
	}

	return nil
}

func (p *Transforms) InitDNSMessageFormat(dm *dnsutils.DNSMessage) {
	if p.config.Filtering.Enable {
		p.FilteringTransform.InitDNSMessage(dm)
	}

	if p.config.GeoIP.Enable {
		p.GeoipTransform.InitDNSMessage(dm)
	}

	if p.config.Suspicious.Enable {
		p.SuspiciousTransform.InitDNSMessage(dm)
	}

	if p.config.Normalize.Enable {
		if p.config.Normalize.AddTld || p.config.Normalize.AddTldPlusOne {
			p.NormalizeTransform.InitDNSMessage(dm)
		}
	}

	if p.config.Extract.Enable {
		if p.config.Extract.AddPayload {
			p.ExtractProcessor.InitDNSMessage(dm)
		}
	}

	if p.config.Reducer.Enable {
		p.ReducerTransform.InitDNSMessage(dm)
	}

	if p.config.MachineLearning.Enable {
		p.MachineLearningTransform.InitDNSMessage(dm)
	}

	if p.config.ATags.Enable {
		p.ATagsTransform.InitDNSMessage(dm)
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
func (p *Transforms) machineLearningTransform(dm *dnsutils.DNSMessage) int {
	p.MachineLearningTransform.AddFeatures(dm)
	return ReturnSuccess
}

func (p *Transforms) suspiciousTransform(dm *dnsutils.DNSMessage) int {
	p.SuspiciousTransform.CheckIfSuspicious(dm)
	return ReturnSuccess
}

func (p *Transforms) geoipTransform(dm *dnsutils.DNSMessage) int {
	geoInfo, err := p.GeoipTransform.Lookup(dm.NetworkInfo.QueryIP)
	if err != nil {
		p.LogError("geoip lookup error %v", err)
		return ReturnError
	}

	dm.Geo.Continent = geoInfo.Continent
	dm.Geo.CountryIsoCode = geoInfo.CountryISOCode
	dm.Geo.City = geoInfo.City
	dm.Geo.AutonomousSystemNumber = geoInfo.ASN
	dm.Geo.AutonomousSystemOrg = geoInfo.ASO

	return ReturnSuccess
}

func (p *Transforms) anonymizeIP(dm *dnsutils.DNSMessage) int {
	dm.NetworkInfo.QueryIP = p.UserPrivacyTransform.AnonymizeIP(dm.NetworkInfo.QueryIP)

	return ReturnSuccess
}

func (p *Transforms) hashIP(dm *dnsutils.DNSMessage) int {
	dm.NetworkInfo.QueryIP = p.UserPrivacyTransform.HashIP(dm.NetworkInfo.QueryIP)
	dm.NetworkInfo.ResponseIP = p.UserPrivacyTransform.HashIP(dm.NetworkInfo.ResponseIP)
	return ReturnSuccess
}

func (p *Transforms) measureLatency(dm *dnsutils.DNSMessage) int {
	p.LatencyTransform.MeasureLatency(dm)
	return ReturnSuccess
}

func (p *Transforms) detectEvictedTimeout(dm *dnsutils.DNSMessage) int {
	p.LatencyTransform.DetectEvictedTimeout(dm)
	return ReturnSuccess
}

func (p *Transforms) minimazeQname(dm *dnsutils.DNSMessage) int {
	dm.DNS.Qname = p.UserPrivacyTransform.MinimazeQname(dm.DNS.Qname)

	return ReturnSuccess
}

func (p *Transforms) addBase64Payload(dm *dnsutils.DNSMessage) int {
	dm.Extracted.Base64Payload = p.ExtractProcessor.AddBase64Payload(dm)
	return ReturnSuccess
}

func (p *Transforms) ProcessMessage(dm *dnsutils.DNSMessage) int {
	// Begin to normalize
	p.NormalizeTransform.ProcessDNSMessage(dm)

	// Traffic filtering ?
	if p.FilteringTransform.CheckIfDrop(dm) {
		return ReturnDrop
	}

	// Traffic reducer ?
	if p.ReducerTransform.ProcessDNSMessage(dm) == ReturnDrop {
		return ReturnDrop
	}

	//  and finaly apply other transformation
	var rCode int
	for _, fn := range p.activeTransforms {
		rCode = fn(dm)
		if rCode != ReturnSuccess {
			return rCode
		}
	}

	return ReturnSuccess
}
