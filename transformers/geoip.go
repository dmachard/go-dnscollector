package transformers

import (
	"fmt"
	"net"
	"strconv"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
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
	Continent, CountryISOCode, City, ASN, ASO string
}

type GeoIPTransform struct {
	GenericTransformer
	dbCountry, dbCity, dbAsn *maxminddb.Reader
}

func NewDNSGeoIPTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *GeoIPTransform {
	t := &GeoIPTransform{GenericTransformer: NewTransformer(config, logger, "geoip", name, instance, nextWorkers)}
	return t
}

func (t *GeoIPTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.GeoIP.Enable {
		if err := t.Open(); err != nil {
			return nil, fmt.Errorf("open error %w", err)
		}
		subtransforms = append(subtransforms, Subtransform{name: "geoip:lookup", processFunc: t.geoipTransform})
	}
	return subtransforms, nil
}

func (t *GeoIPTransform) Reset() {
	if t.config.GeoIP.Enable {
		t.Close()
	}
}

func (t *GeoIPTransform) Open() (err error) {
	// before to open, close all files
	// because open can be called also on reload
	t.Close()

	// open files ?
	if len(t.config.GeoIP.DBCountryFile) > 0 {
		t.dbCountry, err = maxminddb.Open(t.config.GeoIP.DBCountryFile)
		if err != nil {
			return err
		}
		t.LogInfo("country database loaded (%d records)", t.dbCountry.Metadata.NodeCount)
	}

	if len(t.config.GeoIP.DBCityFile) > 0 {
		t.dbCity, err = maxminddb.Open(t.config.GeoIP.DBCityFile)
		if err != nil {
			return err
		}
		t.LogInfo("city database loaded (%d records)", t.dbCity.Metadata.NodeCount)
	}

	if len(t.config.GeoIP.DBASNFile) > 0 {
		t.dbAsn, err = maxminddb.Open(t.config.GeoIP.DBASNFile)
		if err != nil {
			return err
		}
		t.LogInfo("asn database loaded (%d records)", t.dbAsn.Metadata.NodeCount)
	}
	return nil
}

func (t *GeoIPTransform) Close() {
	if t.dbCountry != nil {
		t.dbCountry.Close()
	}
	if t.dbCity != nil {
		t.dbCity.Close()
	}
	if t.dbAsn != nil {
		t.dbAsn.Close()
	}
}

func (t *GeoIPTransform) Lookup(ip string) (GeoRecord, error) {
	record := &MaxminddbRecord{}
	rec := GeoRecord{Continent: "-",
		CountryISOCode: "-",
		City:           "-",
		ASN:            "-",
		ASO:            "-"}

	if t.dbAsn != nil {
		err := t.dbAsn.Lookup(net.ParseIP(ip), &record)
		if err != nil {
			return rec, err
		}
		rec.ASN = strconv.Itoa(record.AutonomousSystemNumber)
		rec.ASO = record.AutonomousSystemOrganization
	}

	if t.dbCity != nil {
		err := t.dbCity.Lookup(net.ParseIP(ip), &record)
		if err != nil {
			return rec, err
		}
		rec.City = record.City.Names["en"]
		rec.CountryISOCode = record.Country.ISOCode
		rec.Continent = record.Continent.Code

	} else if t.dbCountry != nil {
		err := t.dbCountry.Lookup(net.ParseIP(ip), &record)
		if err != nil {
			return rec, err
		}
		rec.CountryISOCode = record.Country.ISOCode
		rec.Continent = record.Continent.Code
	}

	return rec, nil
}

func (t *GeoIPTransform) geoipTransform(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Geo == nil {
		dm.Geo = &dnsutils.TransformDNSGeo{
			CountryIsoCode: "-", City: "-", Continent: "-",
			AutonomousSystemNumber: "-", AutonomousSystemOrg: "-",
		}
	}

	geoInfo, err := t.Lookup(dm.NetworkInfo.QueryIP)
	if err != nil {
		t.LogError("geoip lookup error %v", err)
		return ReturnKeep, err
	}

	dm.Geo.Continent = geoInfo.Continent
	dm.Geo.CountryIsoCode = geoInfo.CountryISOCode
	dm.Geo.City = geoInfo.City
	dm.Geo.AutonomousSystemNumber = geoInfo.ASN
	dm.Geo.AutonomousSystemOrg = geoInfo.ASO

	return ReturnKeep, nil
}
