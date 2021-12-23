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
  "answers": [
    {
      "name": "gmail.google.com",
      "rdatatype": "CNAME",
      "ttl": 19437,
      "rdata": "www3.l.google.com"
    },
    {
      "name": "www3.l.google.com",
      "rdatatype": "A",
      "ttl": 300,
      "rdata": "142.250.74.238"
    }
  ],
  "answers-ns": null,
  "answers-more": null,
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