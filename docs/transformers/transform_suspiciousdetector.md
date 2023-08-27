# Transformer: Suspicious

This feature can be used to tag unusual dns traffic like long domain, large packets and more.

Options:

- `threshold-qname-len`: a length greater than this value for qname will be considered as suspicious
- `threshold-packet-len`: a size greater than this value will be considered as suspicious in bytes
- `threshold-slow`: threshold to set a domain considered as slow regarding latency, value in second
- `common-qtypes`:  common qtypes list
- `unallowed-chars`: unallowed list of characters not acceptable in domain name
- `threshold-max-labels`: maximum number of labels in domains name
- `whitelist-domains`: to ignore some domains

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
    whitelist-domains: [ "\.ip6\.arpa" ]
```

Specific directive(s) available for the text format:

- `suspicious-score`: suspicious score for unusual traffic

When the feature is enabled, the following json field are populated in your DNS message:

Example:

```json
{
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
}
```
