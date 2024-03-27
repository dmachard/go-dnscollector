# Transformer: GeoIP Support

GeoIP maxmind support feature.
The country code can be populated regarding the query IP collected.
To enable this feature, you need to configure the path to your database.

See [Downloads](https://www.maxmind.com/en/accounts/current/geoip/downloads) maxmind page to get the database.

Options:

* `mmdb-country-file` (string)
  > path file to your mmdb country database

* `mmdb-city-file` (string)
  > path file to your mmdb city database

* `mmdb-asn-file` (string)
  > path file to your mmdb asn database

```yaml
transforms:
  geoip:
    mmdb-country-file: "/GeoIP/GeoLite2-Country.mmdb"
    mmdb-city-file: ""
    mmdb-asn-file: ""
```

When the feature is enabled, the following json field are populated in your DNS message:

* `continent`
* `country-isocode`
* `city`
* `as-number`
* `as-owner`

Example:

```json
{
  "geoip": {
    "city": "-",
    "continent": "-",
    "country-isocode": "-",
    "as-number": "1234",
    "as-owner": "Orange"
},
```

Specific directives added:

* `geoip-continent`: continent code
* `geoip-country`: country iso code
* `geoip-city`: city name
* `geoip-as-number`: autonomous system number
* `geoip-as-owner`: autonomous system organization/owner
