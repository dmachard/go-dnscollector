# DNS-collector - Transformers Guide

- [Public suffix](#public-suffix)
- [Normalize](#normalize)
- [User privacy](#user-privacy)
- [GeoIP Support](#geoip-support)
- [DNS filtering](#dns-filtering)
- [Suspicious](#suspicious)

## Transformers

### Public Suffix

Option to add top level domain. For example for `books.amazon.co.uk`, the `TLD`
is `co.uk` and the `TLD+1` is `amazon.co.uk`.

Options:
- `add-tld`: (boolean) add top level domain
- `add-tld-plus-one`: (boolean) add top level domain plus one label

```yaml
transforms:
  public-suffix:
    add-tld: false
    add-tld-plus-one: false
```

### Normalize

Option to convert all domain to lowercase. For example: `Wwww.GooGlE.com` will be equal to `www.google.com`

Options:
- `qname-lowercase`: (boolean) enable or disable lowercase

```yaml
transforms:
  normalize:
    qname-lowercase: true
```

### User Privacy

Use this feature to protect user privacy. This feature can be used to anonymize all IP queries and reduce all qnames to second level.
For example:
- QueryIP 8.8.8.8 will be replaced by 8.8.0.0. IP-Addresses are anonymities by zeroing the host-part of an address.
- Qname mail.google.com be replaced by google.com

Options:
- `anonymize-ip`: (boolean) enable or disable anomymiser ip
- `minimaze-qname`: (boolean) keep only the second level domain

```yaml
transforms:
  user-privacy:
    anonymize-ip: false
    minimaze-qname: false
```

### GeoIP Support

GeoIP maxmind support feature.
The country code can be populated regarding the query IP collected.
To enable this feature, you need to configure the path to your database.

See [Downloads](https://www.maxmind.com/en/accounts/current/geoip/downloads) maxmind page to get the database.

Options:
- `mmdb-country-file`: (string) path file to your mmdb country database
- `mmdb-city-file`: (string) path file to your mmdb city database
- `mmdb-asn-file`: (string) path file to your mmdb asn database

```yaml
transforms:
  geoip:
    mmdb-country-file: "/GeoIP/GeoLite2-Country.mmdb"
    mmdb-city-file: ""
    mmdb-asn-file: ""
```

When the feature is enabled, the following json field are populated:
- `continent`
- `country-isocode`
- `city`
- `as-number`
- `as-owner`

Example:

```json
{
  ...
  "geo": {
    "city": "-",
    "continent": "-",
    "country-isocode": "-"
  },
  "network": {
    ...
    "as-number": 1234,
    "as-owner": "Orange",
  },
  ...
}
```

### DNS filtering

The filtering feature can be used to ignore some queries or replies according to:
- qname
- return code
- query ip
- sampling rate

This feature can be useful to increase logging performance..

Options:
- `drop-fqdn-file`: (string) path file to a fqdn drop list, domains list must be a full qualified domain name
- `drop-domain-file`: (string) path file to domain drop list, domains list can be a partial domain name with regexp expression
- `keep-fqdn-file`: (string) path file to a fqdn keep list (all others are dropped), domains list must be a full qualified domain name
- `keep-domain-file`: (string) path file to domain keep list (all others are dropped), domains list can be a partial domain name with regexp expression
- `drop-queryip-file`: (string) path file to the query ip or ip prefix drop list
- `keep-queryip-file`: (string) path file to the query ip or ip prefix keep list, addresses in both drop and keep are always kept
- `drop-rcodes`: (list of string) rcode list, empty by default
- `log-queries`: (boolean) drop all queries on false
- `log-replies`: (boolean)  drop all replies on false
- `downsample`: (integer) only keep 1 out of every `downsample` records, e.g. if set to 20, then this will return every 20th record, dropping 95% of queries 

Default values:

```yaml
transforms:
  filtering:
    drop-fqdn-file: ""
    drop-domain-file: ""
    keep-fqdn-file: ""
    keep-domain-file: ""
    drop-queryip-file: ""
    keep-queryip-file: ""
    drop-rcodes: []
    log-queries: true
    log-replies: true
    downsample: 0
```

Domain list with regex example:

```
(mail|wwww).google.com
github.com
```

### Suspicious

This feature can be used to tag unusual dns traffic like long domain, large packets and more.

Options:
- `threshold-qname-len`: a length greater than this value for qname will be considered as suspicious
- `threshold-packet-len`: a size greater than this value will be considered as suspicious in bytes
- `threshold-slow`: threshold to set a domain considered as slow regarding latency, value in second
- `common-qtypes`:  common qtypes list 
- `unallowed-chars`: unallowed list of characters not acceptable in domain name
- `hreshold-max-labels`: maximum number of labels in domains name

Default values:

```yaml
transforms:
  suspicious:
    threshold-qname-len: 100
    threshold-packet-len: 1000
    threshold-slow: 1.0
    common-qtypes:  [ "A", "AAAA", "CNAME", "TXT", "PTR", "NAPTR", "DNSKEY", "SRV", "SOA", "NS", "MX", "DS" ]
    unallowed-chars: [ "\"", "==", "/", ":" ]
    threshold-max-labels: 10
```
