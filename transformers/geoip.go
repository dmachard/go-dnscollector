package transformers

import (
	"net"
	"strconv"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
	"github.com/oschwald/maxminddb-golang"
)

type MaxminddbRecord struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	AutonomousSystemNumber       int    `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

type GeoRecord struct {
	Continent      string
	CountryISOCode string
	City           string
	ASN            string
	ASO            string
}

type GeoIpProcessor struct {
	config    *dnsutils.ConfigTransformers
	logger    *logger.Logger
	dbCountry *maxminddb.Reader
	dbCity    *maxminddb.Reader
	dbAsn     *maxminddb.Reader
	enabled   bool
}

func NewDnsGeoIpProcessor(config *dnsutils.ConfigTransformers, logger *logger.Logger) GeoIpProcessor {
	d := GeoIpProcessor{
		config: config,
		logger: logger,
	}

	return d
}

func (p *GeoIpProcessor) LogInfo(msg string, v ...interface{}) {
	p.logger.Info("Subprocessor GeoIP - "+msg, v...)
}

func (p *GeoIpProcessor) LogError(msg string, v ...interface{}) {
	p.logger.Error("Subprocessor GeoIP - "+msg, v...)
}

func (p *GeoIpProcessor) InitDnsMessage(dm *dnsutils.DnsMessage) {
	dm.Geo = &dnsutils.DnsGeo{
		CountryIsoCode:         "-",
		City:                   "-",
		Continent:              "-",
		AutonomousSystemNumber: "-",
		AutonomousSystemOrg:    "-",
	}
}

func (p *GeoIpProcessor) Open() (err error) {
	if len(p.config.GeoIP.DbCountryFile) > 0 {
		p.dbCountry, err = maxminddb.Open(p.config.GeoIP.DbCountryFile)
		if err != nil {
			p.enabled = false
			return
		}
		p.enabled = true
		p.LogInfo("country database loaded (%d records)", p.dbCountry.Metadata.NodeCount)
	}

	if len(p.config.GeoIP.DbCityFile) > 0 {
		p.dbCity, err = maxminddb.Open(p.config.GeoIP.DbCityFile)
		if err != nil {
			p.enabled = false
			return
		}
		p.enabled = true
		p.LogInfo("city database loaded (%d records)", p.dbCity.Metadata.NodeCount)
	}

	if len(p.config.GeoIP.DbAsnFile) > 0 {
		p.dbAsn, err = maxminddb.Open(p.config.GeoIP.DbAsnFile)
		if err != nil {
			p.enabled = false
			return
		}
		p.enabled = true
		p.LogInfo("asn database loaded (%d records)", p.dbAsn.Metadata.NodeCount)
	}
	return nil
}

func (p *GeoIpProcessor) IsEnabled() bool {
	return p.enabled
}

func (p *GeoIpProcessor) Close() {
	if p.dbCountry != nil {
		p.dbCountry.Close()
	}
	if p.dbCity != nil {
		p.dbCity.Close()
	}
	if p.dbAsn != nil {
		p.dbAsn.Close()
	}
}

func (p *GeoIpProcessor) Lookup(ip string) (GeoRecord, error) {
	record := &MaxminddbRecord{}
	rec := GeoRecord{Continent: "-",
		CountryISOCode: "-",
		City:           "-",
		ASN:            "-",
		ASO:            "-"}

	if p.dbAsn != nil {
		err := p.dbAsn.Lookup(net.ParseIP(ip), &record)
		if err != nil {
			return rec, err
		}
		rec.ASN = strconv.Itoa(record.AutonomousSystemNumber)
		rec.ASO = record.AutonomousSystemOrganization
	}

	if p.dbCity != nil {
		err := p.dbCity.Lookup(net.ParseIP(ip), &record)
		if err != nil {
			return rec, err
		}
		rec.City = record.City.Names["en"]
		rec.CountryISOCode = record.Country.ISOCode
		rec.Continent = record.Continent.Code

	} else {
		if p.dbCountry != nil {
			err := p.dbCountry.Lookup(net.ParseIP(ip), &record)
			if err != nil {
				return rec, err
			}
			rec.CountryISOCode = record.Country.ISOCode
			rec.Continent = record.Continent.Code
		}
	}

	return rec, nil
}
