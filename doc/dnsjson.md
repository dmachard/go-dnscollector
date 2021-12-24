# DnsCollector - DNS JSON encoding


The dns collector enable to transform dns queries or replies in JSON format.

Format:

```json
{
  "network": {
    "family": "INET",
    "protocol": "UDP",
    "query-ip": "192.168.1.210",
    "query-port": "60981",
    "response-ip": "192.168.1.210",
    "response-port": "53",
    "as-number": "-",
    "as-owner": "-"
  },
  "dns": {
    "operation": "CLIENT_RESPONSE",
    "length": 51,
    "rcode": "NOERROR",
    "qname": "eu.org",
    "qtype": "A",
    "flags": {
      "qr": true,
      "tc": false,
      "aa": false,
      "ra": true,
      "ad": true
    },
    "resource-records": {
      "an": [
        {
          "name": "eu.org",
          "rdatatype": "A",
          "ttl": 2797,
          "rdata": "78.194.169.74"
        }
      ],
      "ns": [],
      "ar": []
    },
    "malformed-packet": 0,
    "latency": "0.013856"
  },
  "identity": "dnsdist1",
  "timestamp-rfc3339ns": "2021-12-24T12:23:45.221327147Z",
  "geo": {
    "city": "-",
    "continent": "-",
    "country-isocode": "-"
  }
}
```