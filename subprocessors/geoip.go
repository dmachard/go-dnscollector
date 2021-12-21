package subprocessors

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
	config    *dnsutils.Config
	logger    *logger.Logger
	dbCountry *maxminddb.Reader
	dbCity    *maxminddb.Reader
	dbAsn     *maxminddb.Reader
	enabled   bool
}

func NewDnsGeoIpProcessor(config *dnsutils.Config, logger *logger.Logger) GeoIpProcessor {
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

func (p *GeoIpProcessor) Open() (err error) {
	if len(p.config.Subprocessors.GeoIP.DbCountryFile) > 0 {
		p.dbCountry, err = maxminddb.Open(p.config.Subprocessors.GeoIP.DbCountryFile)
		if err != nil {
			p.enabled = false
			return
		}
		p.enabled = true
		p.LogInfo("country database loaded")
	}

	if len(p.config.Subprocessors.GeoIP.DbCityFile) > 0 {
		p.dbCity, err = maxminddb.Open(p.config.Subprocessors.GeoIP.DbCityFile)
		if err != nil {
			p.enabled = false
			return
		}
		p.enabled = true
		p.LogInfo("city database loaded")
	}

	if len(p.config.Subprocessors.GeoIP.DbAsnFile) > 0 {
		p.dbAsn, err = maxminddb.Open(p.config.Subprocessors.GeoIP.DbAsnFile)
		if err != nil {
			p.enabled = false
			return
		}
		p.enabled = true
		p.LogInfo("asn database loaded")
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
	rec := &GeoRecord{Continent: "-",
		CountryISOCode: "-",
		City:           "-",
		ASN:            "-",
		ASO:            "-"}

	if len(p.config.Subprocessors.GeoIP.DbAsnFile) > 0 {
		err := p.dbAsn.Lookup(net.ParseIP(ip), &record)
		if err != nil {
			return *rec, err
		}
		rec.ASN = strconv.Itoa(record.AutonomousSystemNumber)
		rec.ASO = record.AutonomousSystemOrganization
	}

	if len(p.config.Subprocessors.GeoIP.DbCityFile) > 0 {
		err := p.dbCity.Lookup(net.ParseIP(ip), &record)
		if err != nil {
			return *rec, err
		}
		rec.City = record.City.Names["en"]
		rec.CountryISOCode = record.Country.ISOCode
		rec.Continent = record.Continent.Code

	} else {
		if len(p.config.Subprocessors.GeoIP.DbCountryFile) > 0 {
			err := p.dbCountry.Lookup(net.ParseIP(ip), &record)
			if err != nil {
				return *rec, err
			}
			rec.CountryISOCode = record.Country.ISOCode
			rec.Continent = record.Continent.Code
		}
	}

	return *rec, nil
}
