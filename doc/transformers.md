# DNS-collector - Transformers Guide

- [Normalize](#normalize)
- [User privacy](#user-privacy)
- [GeoIP Support](#geoip-support)
- [DNS filtering](#dns-filtering)
- [Suspicious](#suspicious)
- [Latency](#latency)

## Transformers

### Normalize

This transformer can be used:
- to convert all domain to lowercase. For example: `Wwww.GooGlE.com` will be equal to `www.google.com`
- to add top level domain. For example for `books.amazon.co.uk`, the `TLD`
is `co.uk` and the `TLD+1` is `amazon.co.uk`.
- to use small text form. For example: `CLIENT_QUERY` will be replaced by `CQ`

Options:
- `qname-lowercase`: (boolean) enable or disable lowercase
- `add-tld`: (boolean) add top level domain
- `add-tld-plus-one`: (boolean) add top level domain plus one label
- `quiet-text`: (boolean) Quiet text mode to reduce the size of the logs

```yaml
transforms:
  normalize:
    qname-lowercase: true
    add-tld: false
    add-tld-plus-one: false
    quiet-text: false
```

The following dnstap flag message will be replaced with the small form:
- AUTH_QUERY: `AQ`
- AUTH_RESPONSE: `AR`
- RESOLVER_QUERY: `RQ`
- RESOLVER_RESPONSE: `RR`
- CLIENT_QUERY: `CQ`
- CLIENT_RESPONSE: `CR`
- FORWARDER_QUERY: `FQ`
- FORWARDER_RESPONSE: `FR`
- STUB_QUERY: `SQ`
- STUB_RESPONSE: `SR`
- TOOL_QUERY: `TQ`
- TOOL_RESPONSE: `TR`

The following dns flag message will be replaced with the small form:
- QUERY: `Q`
- REPLY: `R`

If one of add-tld  options is enable then the following json field are populated in your DNS message:

Example:

```json
"publicsuffix": {
  "etld+1": "eu.org",
  "tld": "org",
}
```

Specific directives added for text format:
- `publicsuffix-tld`: [Public Suffix](https://publicsuffix.org/) of the DNS QNAME
- `publicsuffix-etld+1`: [Public Suffix](https://publicsuffix.org/) plus one label of the DNS QNAME

### User Privacy

Use this feature to protect user privacy. This feature can be used to anonymize all IP queries and reduce all qnames to second level.
For example:
- QueryIP 8.8.8.8 will be replaced by 8.8.0.0. IP-Addresses are anonymities by zeroing the host-part of an address.
- Qname mail.google.com be replaced by google.com

Options:
- `anonymize-ip`: (boolean) enable or disable anomymiser ip
- `hash-ip`: (boolean) hash query and response IP with sha1
- `minimaze-qname`: (boolean) keep only the second level domain

```yaml
transforms:
  user-privacy:
    anonymize-ip: false
    hash-ip: false
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

When the feature is enabled, the following json field are populated in your DNS message:
- `continent`
- `country-isocode`
- `city`
- `as-number`
- `as-owner`

Example:

```json
{
  "geoip": {
    "city": "-",
    "continent": "-",
    "country-isocode": "-",
    "as-number": 1234,
    "as-owner": "Orange",
  },
```

Specific directives added:
- `geoip-continent`: continent code
- `geoip-country`: country iso code
- `geoip-city`: city name
- `geoip-as-number`: autonomous system number
- `geoip-as-owner`: autonomous system organization/owner

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

When the feature is enabled, the following json field are populated in your DNS message:

Example:

```json
  "suspicious": {
    "score": 0.0,
    "malformed-packet": false,
    "large-pkt": false,
    "long-domain": false,
    "slow-domain": false,
    "unallowed-chars": false,
    "uncommon-qtypes": false,
    "excessive-number-labels": false,
  }
```

Specific directive(s) added:
- `suspicious-score`: suspicious score for unusual traffic

### Latency


Use this feature to compute latency and detect queries timeout

Options:
- `measure-latency`: (boolean) measure latency between replies and queries
- `detect-evicted-queries`: (boolean) Detect evicted queries

```yaml
transforms:
  user-privacy:
    anonymize-ip: false
    hash-ip: false
    minimaze-qname: false
```
