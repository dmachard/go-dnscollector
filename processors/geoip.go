package processors

import (
	"net"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/oschwald/maxminddb-golang"
)

type CountryDb struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type GeoIpProcessor struct {
	config  *dnsutils.Config
	db      *maxminddb.Reader
	enabled bool
	result  CountryDb
}

func NewDnsGeoIpProcessor(config *dnsutils.Config) GeoIpProcessor {
	d := GeoIpProcessor{
		config: config,
	}

	return d
}

func (p *GeoIpProcessor) Open() (err error) {
	if len(p.config.Processors.GeoIP.DbFile) > 0 {
		p.db, err = maxminddb.Open(p.config.Processors.GeoIP.DbFile)
		if err != nil {
			p.enabled = false
			return
		}
		p.enabled = true
	}
	return nil
}

func (p *GeoIpProcessor) IsEnabled() bool {
	return p.enabled
}

func (p *GeoIpProcessor) Close() {
	if p.db != nil {
		p.db.Close()
	}
}

func (p *GeoIpProcessor) Lookup(ip string) (code string, err error) {
	code = ""
	err = p.db.Lookup(net.ParseIP(ip), &p.result)
	if err != nil {
		return code, err
	}
	code = p.result.Country.ISOCode
	return
}
