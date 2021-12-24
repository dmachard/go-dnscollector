# DnsCollector - DNS JSON encoding


The dns collector enable to transform dns queries or replies in JSON format.

Format:

```json
{
  "network": {
    "family": "INET",
    "protocol": "UDP",
    "query-ip": "192.168.1.210",
    "query-port": "38599",
    "response-ip": "192.168.1.210",
    "response-port": "53",
    "as-number": "-",
    "as-owner": "-"
  },
  "operation": "CLIENT_RESPONSE",
  "identity": "dnsdist1",
  "length": 82,
  "rcode": "NOERROR",
  "qname": "gmail.google.com",
  "qtype": "A",
  "latency": "0.014125",
  "timestamp-rfc3339ns": "2021-12-23T16:49:29.329980063Z",
  "resource-records": {
    "answers": [
      {
        "name": "eu.org",
        "rdatatype": "A",
        "ttl": 2725,
        "rdata": "78.194.169.74"
      }
    ],
    "nameservers": [],
    "records": []
  },
  "malformed-packet": 0,
  "flags": {
    "qr": false,
    "tc": false,
    "aa": false,
    "ra": true,
    "ad": true
  },
  "geo": {
    "city": "-",
    "continent": "-",
    "country-isocode": "-"
  }
}
```