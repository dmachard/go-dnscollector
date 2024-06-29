# DNS-collector - JSON encoding

The `DNS-collector` enables the transformation of DNS queries or replies into `JSON` format.
The JSON format contains DNS messages with additionnal metadata added by transformers or collectors.

The default JSON payload parts:

- `network`:  Query/response IP and port, the protocol, and family used.
- `dnstap`: Message type, arrival packet time, latency.
- `dns`: DNS fields.
- `edns`: Extended DNS options.

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
    "id": 23455,
    "qclass": "IN",
    "questions-count": 0,
    "flags": {
      "qr": true,
      "tc": false,
      "aa": false,
      "ra": true,
      "ad": true,
      "rd": true,
      "cd": true
    },
    "resource-records": {
      "an": [
        {
          "name": "eu.org",
          "rdatatype": "A",
          "ttl": 2797,
          "rdata": "78.194.169.74",
          "class": "IN"
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
    "peer-name": "172.16.0.2",
    "version": "-",
    "extra": "-",
    "timestamp-rfc3339ns": "2021-12-27T14:33:44.559002118Z",
    "latency": 0.014617,
    "policy-rule": "-",
    "policy-type": "-",
    "policy-action": "-",
    "policy-match": "-",
    "policy-value": "-",
    "query-zone": "-",
  }
}
```

## Flat JSON format (recommended)

At times, a single level key-value output in JSON is easier to ingest than multi-level JSON structures.
Utilizing `flat-json` delivers every output field as its own key/value pair but requires more processing
on the host running DNS-collector.

This format is recommended because custom relabeling can be applied on it (drop keys or rename it).

Here's a flat JSON output formatted using `jq`:

```json
{
  "dns.flags.aa": false,
  "dns.flags.ad": false,
  "dns.flags.qr": true,
  "dns.flags.ra": true,
  "dns.flags.tc": false,
  "dns.flags.rd": false,
  "dns.flags.cd": false,
  "dns.length": 82,
  "dns.malformed-packet": false,
  "dns.id": 34555,
  "dns.opcode": 0,
  "dns.qname": "google.nl",
  "dns.qtype": "A",
  "dns.rcode": "NOERROR",
  "dns.qclass": "IN",
  "dns.questions-count": 0,
  "dns.resource-records.an.0.name": "google.nl",
  "dns.resource-records.an.0.rdata": "142.251.39.99",
  "dns.resource-records.an.0.rdatatype": "A",
  "dns.resource-records.an.0.ttl": 300,
  "dns.resource-records.an.0.class": "IN",
  "dns.resource-records.ar": "-",
  "dns.resource-records.ns": "-",
  "dnstap.identity": "foo",
  "dnstap.peer-name": "172.16.0.2",
  "dnstap.latency": 0.000000,
  "dnstap.operation": "CLIENT_RESPONSE",
  "dnstap.timestamp-rfc3339ns": "2023-03-31T10:14:46.664534902Z",
  "dnstap.version": "BIND 9.18.13-1+ubuntu20.04.1+isc+1-Ubuntu",
  "dnstap.extra": "-",
  "dnstap.policy-rule": "-",
  "dnstap.policy-type": "-",
  "dnstap.policy-action": "-",
  "dnstap.policy-match": "-",
  "dnstap.policy-value": "-",
  "dnstap.query-zone": "-",
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

## Extended JSON format

This JSON message can be extended by collector(s):

- [PowerDNS collector](collectors/collector_powerdns.md)

This JSON message can be also extended by transformer(s):

- [Atags](transformers/transformer_atags.md)
- [GeoIP](transformers/transformer_geoip.md)
- [Suspicious traffic detector](transformers/transform_suspiciousdetector.md)
- [Public suffix](transformers/transform_normalize.md)
- [Traffic reducer](transformers/transform_trafficreducer.md)
- [Traffic filtering](transformers/transformer_trafficfiltering.md)