# DnsCollector - DNS JSON encoding


The dns collector enable to transform dns queries or replies in JSON format.
A JSON format contains dns message with additionnal metadata.

Main part of a JSON message:
- `network`:  query/response ip and port, the protocol and family used
- `dnstap`: message type, arrival packet time, latency.
- `dns`: dns fields
- `edns`: extended dns options
- `geo`: contains country, continent and city informations

Example:

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
    "length": 51,
    "rcode": "NOERROR",
    "qname": "eu.org",
    "qname-effective-tld-plus-one": "eu.org",
    "qname-public-suffix": "org",
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
  },
  "edns": {
    "udp-size": 512,
    "rcode": 0,
    "version": 0,
    "dnssec-ok": 0,
    "options": [
      {
        "code": 15,
        "name": "ERRORS",
        "data": "49152 - Provided ECS includes 32 bits, but no more than 24 are allowed."
      },
      {
        "code": 8,
        "name": "CSUBNET",
        "data": "192.168.0.0/32"
      }
    ]
  },
  "dnstap": {
    "operation": "CLIENT_RESPONSE",
    "identity": "dnsdist1",
    "timestamp-rfc3339ns": "2021-12-27T14:33:44.559002118Z",
    "latency": "0.014617"
  },
  "geo": {
    "city": "-",
    "continent": "-",
    "country-isocode": "-"
  }
}
```
