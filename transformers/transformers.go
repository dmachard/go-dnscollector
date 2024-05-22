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
	ReturnKeep    = 1
	ReturnDrop    = 2
	ReturnError   = 3
)

type Subtransform struct {
	name        string
	processFunc func(dm *dnsutils.DNSMessage) int
}

type Transformation interface {
	GetTransforms() ([]Subtransform, error)
	ReloadConfig(config *pkgconfig.ConfigTransformers)
}

type GenericTransformer struct {
	config            *pkgconfig.ConfigTransformers
	logger            *logger.Logger
	name              string
	nextWorkers       []chan dnsutils.DNSMessage
	LogInfo, LogError func(msg string, v ...interface{})
}

func NewTransformer(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, workerName string, instance int, nextWorkers []chan dnsutils.DNSMessage) GenericTransformer {
	t := GenericTransformer{config: config, logger: logger, nextWorkers: nextWorkers, name: name}

	t.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("worker - [%s] [conn=#%d] [transform=%s] - ", workerName, instance, name)
		logger.Info(log+msg, v...)
	}

	t.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("worker - [%s] [conn=#%d] [transform=%s] - ", workerName, instance, name)
		logger.Error(log+msg, v...)
	}
	return t
}

func (t *GenericTransformer) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	t.config = config
}

type TransformEntry struct {
	Transformation
}

type Transforms struct {
	config   *pkgconfig.ConfigTransformers
	logger   *logger.Logger
	name     string
	instance int

	SuspiciousTransform      SuspiciousTransform
	GeoipTransform           GeoIPProcessor
	UserPrivacyTransform     UserPrivacyProcessor
	LatencyTransform         *LatencyProcessor
	ExtractProcessor         ExtractProcessor
	MachineLearningTransform MlProcessor

	availableTransforms []TransformEntry
	activeTransforms    []func(dm *dnsutils.DNSMessage) int
}

func NewTransforms(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, outChannels []chan dnsutils.DNSMessage, instance int) Transforms {

	d := Transforms{config: config, logger: logger, name: name, instance: instance}

	// order definition important
	d.availableTransforms = append(d.availableTransforms, TransformEntry{NewNormalizeTransform(config, logger, name, instance, outChannels)})
	d.availableTransforms = append(d.availableTransforms, TransformEntry{NewFilteringTransform(config, logger, name, instance, outChannels)})
	d.availableTransforms = append(d.availableTransforms, TransformEntry{NewReducerTransform(config, logger, name, instance, outChannels)})
	d.availableTransforms = append(d.availableTransforms, TransformEntry{NewATagsTransform(config, logger, name, instance, outChannels)})
	d.availableTransforms = append(d.availableTransforms, TransformEntry{NewRelabelTransform(config, logger, name, instance, outChannels)})

	d.SuspiciousTransform = NewSuspiciousTransform(config, logger, name, instance, outChannels)
	d.ExtractProcessor = NewExtractTransform(config, logger, name, instance, outChannels)
	d.LatencyTransform = NewLatencyTransform(config, logger, name, instance, outChannels)
	d.UserPrivacyTransform = NewUserPrivacyTransform(config, logger, name, instance, outChannels)
	d.GeoipTransform = NewDNSGeoIPTransform(config, logger, name, instance, outChannels)
	d.MachineLearningTransform = NewMachineLearningTransform(config, logger, name, instance, outChannels)

	d.Prepare()
	return d
}

func (p *Transforms) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config

	p.GeoipTransform.ReloadConfig(config)
	p.UserPrivacyTransform.ReloadConfig(config)
	p.LatencyTransform.ReloadConfig(config)
	p.SuspiciousTransform.ReloadConfig(config)
	p.ExtractProcessor.ReloadConfig(config)
	p.MachineLearningTransform.ReloadConfig(config)

	for _, transform := range p.availableTransforms {
		transform.ReloadConfig(config)
	}

	p.Prepare()
}

func (p *Transforms) Prepare() error {
	// clean the slice
	p.activeTransforms = p.activeTransforms[:0]
	tranformsList := []string{}

	for _, transform := range p.availableTransforms {
		subtransforms, err := transform.GetTransforms()
		if err != nil {
			p.LogError("error on init subtransforms:", err)
			continue
		}
		for _, subtransform := range subtransforms {
			p.activeTransforms = append(p.activeTransforms, subtransform.processFunc)
			tranformsList = append(tranformsList, subtransform.name)
		}
	}

	if len(tranformsList) > 0 {
		p.LogInfo("transformers applied: %v", tranformsList)
	}

	var prefixlog string
	if p.instance > 0 {
		prefixlog = fmt.Sprintf("conn #%d - ", p.instance)
	} else {
		prefixlog = ""
	}

	if p.config.GeoIP.Enable {
		p.activeTransforms = append(p.activeTransforms, p.geoipTransform)
		p.LogInfo(prefixlog + "transformer=geoip is " + enabled)

		if err := p.GeoipTransform.Open(); err != nil {
			p.LogError(prefixlog+"transformer=geoip - open error %v", err)
		}
	}

	if p.config.UserPrivacy.Enable {
		// Apply user privacy on qname and query ip
		if p.config.UserPrivacy.AnonymizeIP {
			p.activeTransforms = append(p.activeTransforms, p.anonymizeIP)
			p.LogInfo(prefixlog + "transformer=ip_anonymization is enabled")
		}

		if p.config.UserPrivacy.MinimazeQname {
			p.activeTransforms = append(p.activeTransforms, p.minimazeQname)
			p.LogInfo(prefixlog + "transformer=minimaze_qname is enabled")
		}

		if p.config.UserPrivacy.HashIP {
			p.activeTransforms = append(p.activeTransforms, p.hashIP)
			p.LogInfo(prefixlog + "transformer=hash_ip is enabled")
		}
	}

	if p.config.Latency.Enable {
		if p.config.Latency.MeasureLatency {
			p.activeTransforms = append(p.activeTransforms, p.measureLatency)
			p.LogInfo(prefixlog + "transformer=measure_latency is enabled")
		}
		if p.config.Latency.UnansweredQueries {
			p.activeTransforms = append(p.activeTransforms, p.detectEvictedTimeout)
			p.LogInfo(prefixlog + "transformer=unanswered_queries is enabled")
		}
	}

	if p.config.Suspicious.Enable {
		p.activeTransforms = append(p.activeTransforms, p.suspiciousTransform)
		p.LogInfo(prefixlog + "transformer=suspicious is " + enabled)
	}

	if p.config.Extract.Enable {
		if p.config.Extract.AddPayload {
			p.activeTransforms = append(p.activeTransforms, p.addBase64Payload)
			p.LogInfo(prefixlog + "transformer=extract is enabled")
		}
	}

	if p.config.MachineLearning.Enable {
		p.activeTransforms = append(p.activeTransforms, p.machineLearningTransform)
		p.LogInfo(prefixlog + "transformer=machinelearning is" + enabled)
	}

	return nil
}

func (p *Transforms) InitDNSMessageFormat(dm *dnsutils.DNSMessage) {
	if p.config.GeoIP.Enable {
		p.GeoipTransform.InitDNSMessage(dm)
	}

	if p.config.Suspicious.Enable {
		p.SuspiciousTransform.InitDNSMessage(dm)
	}

	if p.config.Extract.Enable {
		if p.config.Extract.AddPayload {
			p.ExtractProcessor.InitDNSMessage(dm)
		}
	}

	if p.config.MachineLearning.Enable {
		p.MachineLearningTransform.InitDNSMessage(dm)
	}
}

func (p *Transforms) Reset() {
	if p.config.GeoIP.Enable {
		p.GeoipTransform.Close()
	}
}

func (p *Transforms) LogInfo(msg string, v ...interface{}) {
	p.logger.Info(pkgconfig.PrefixLogTransformer+"["+p.name+"] "+msg, v...)
}

func (p *Transforms) LogError(msg string, v ...interface{}) {
	p.logger.Error(pkgconfig.PrefixLogTransformer+"["+p.name+"] "+msg, v...)
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
	for _, transform := range p.activeTransforms {
		if transform(dm) == ReturnDrop {
			return ReturnDrop
		}
	}
	return ReturnKeep
}
