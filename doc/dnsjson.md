# DnsCollector - DNS JSON encoding


The dns collector enable to transform dns queries or replies in JSON format.
A JSON format contains dns message with additionnal metadata added by transformers or collectors.

Default JSON payload::
- `network`:  query/response ip and port, the protocol and family used
- `dnstap`: message type, arrival packet time, latency.
- `dns`: dns fields
- `edns`: extended dns options

Example:

```json
{
  "network": {
    "family": "INET",
    "protocol": "UDP",
    "query-ip": "192.168.1.210",
    "query-port": "60981",
    "response-ip": "192.168.1.210",
    "response-port": "53"
  },
  "dns": {
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
    "version": "-",
    "timestamp-rfc3339ns": "2021-12-27T14:33:44.559002118Z",
    "latency": "0.014617"
  }
}
```

This JSON message can be extended by:
- [PowerDNS collector](powerdns.md#json-format)
- [GeoIP transformer](transformers.md#geoip-support)
- [Suspicious traffic transformer](transformers.md#suspicious)
- [Public suffix transformer](transformers.md#normalize)

## Flat JSON export format
Sometimes, a single level key-value output in JSON is easier to ingest than multi-level JSON.
Using flat-json requires more processing on the host running go-dnscollector but delivers every output field as its own key/value pair. Here's a flat-json output as formatted by `jq`:

```json
{
  "dns.flags.aa": false,
  "dns.flags.ad": false,
  "dns.flags.qr": true,
  "dns.flags.ra": true,
  "dns.flags.tc": false,
  "dns.length": 82,
  "dns.malformed-packet": false,
  "dns.opcode": 0,
  "dns.qname": "google.nl",
  "dns.qtype": "A",
  "dns.rcode": "NOERROR",
  "dns.resource-records.an.0.name": "google.nl",
  "dns.resource-records.an.0.rdata": "142.251.39.99",
  "dns.resource-records.an.0.rdatatype": "A",
  "dns.resource-records.an.0.ttl": 300,
  "dns.resource-records.ar": [],
  "dns.resource-records.ns": [],
  "dnstap.identity": "foo",
  "dnstap.latency": "0.000000",
  "dnstap.operation": "CLIENT_RESPONSE",
  "dnstap.timestamp-rfc3339ns": "2023-03-31T10:14:46.664534902Z",
  "dnstap.version": "BIND 9.18.13-1+ubuntu20.04.1+isc+1-Ubuntu",
  "edns.dnssec-ok": 0,
  "edns.options.0.code": 10,
  "edns.options.0.data": "-",
  "edns.options.0.name": "COOKIE",
  "edns.rcode": 0,
  "edns.udp-size": 1232,
  "edns.version": 0,
  "network.family": "IPv4",
  "network.ip-defragmented": false,
  "network.protocol": "UDP",
  "network.query-ip": "127.0.0.1",
  "network.query-port": "36232",
  "network.response-ip": "127.0.0.1",
  "network.response-port": "53",
  "network.tcp-reassembled": false,
}
```
