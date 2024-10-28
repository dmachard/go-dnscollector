# DNS-collector - DNS conversions

## Overview

The DNScollector can convert the DNS traffic captured from DNStap stream or network streamdn and transform it to 
several outputs format
- text format inline
- JSON advanced structure
- Flat JSON (key/value)
- Jinja templating
- PCAP
- DNStap

## Text format inline

The text format can be customized with the following directives.

Default directives:

- `timestamp-rfc3339ns`: timestamp rfc3339 format, with nano support
- `timestamp-unixms`: unix timestamp with ms support
- `timestamp-unixus`: unix timestamp with us support
- `timestamp-unixns`: unix timestamp with nano support
- `localtime`: local time
- `identity`: dnstap identity
- `peer-name`: hostname or ip address of the dnstap sender
- `version`: dnstap version
- `extra`: dnstap extra as string
- `operation`: dnstap operation
- `policy-rule`: dnstap policy rule
- `policy-type`: dnstap policy type
- `policy-action`: dnstap policy action
- `policy-match`: dnstap policy match
- `policy-value`: dnstap policy value
- `query-zone`: dnstap query zone
- `opcode`: dns opcode (integer)
- `rcode`: dns return code
- `queryip`: dns query ip
- `queryport`: dns query port
- `responseip`: dns response ip
- `responseport`: dns response port
- `id`: dns id
- `family`: ip protocol version INET or INET6
- `protocol`: protocol UDP, TCP
- `length`: the length of the query or reply in bytes
- `length-unit`: the length of the query or reply in bytes with unit (`b`)
- `qtype`: dns query type
- `qclass`: dns query class
- `qname`: dns query name
- `latency`: computed latency between queries and replies
- `qdcount`: the number of question
- `ancount`: the number of answer
- `arcount`: the number of additionnal answer
- `nscount`: the number of nameserver
- `ttl`: answer ttl, only the first one
- `answer`: rdata answer, only the first one, prefer to use the JSON format if you wamt all answers
- `malformed`: malformed dns packet, integer value 1/0
- `qr`: query or reply flag, string value Q/R
- `tc`: flag truncated response
- `aa`: flag authoritative answer
- `ra`: flag recursion available
- `ad`: flag authenticated data
- `df`: flag when ip defragmented occured
- `tr`: flag when tcp reassembled occured
- `edns-csubnet`: display client subnet info

The default text format can be send in the global config or invidually on each loggers, it's your choice
Here the default format.

```yaml
global:
  text-format: "timestamp-rfc3339ns identity qr operation rcode queryip queryport family protocol length-unit qname qtype latency ttl"
```

Output example:

```bash
2023-04-08T18:27:29.268465Z unbound CLIENT_QUERY NOERROR 127.0.0.1 39028 IPv4 UDP 50b google.fr A 0.000000
2023-04-08T18:27:29.268575Z unbound FORWARDER_QUERY NOERROR 0.0.0.0 20817 IPv4 UDP 38b google.fr A 0.000000
2023-04-08T18:27:29.278929Z unbound FORWARDER_RESPONSE NOERROR 0.0.0.0 20817 IPv4 UDP 54b google.fr A 0.000000
2023-04-08T18:27:29.279039Z unbound CLIENT_RESPONSE NOERROR 127.0.0.1 39028 IPv4 UDP 54b google.fr A 0.000000

```

If you require a output format like CSV, the delimiter can be configured with the `text-format-delimiter` option.
The default separator is [space]. text-format can contain raw text enclosed by curly braces, eg

```yaml
global:
  text-format: "timestamp-rfc3339ns identity operation rcode queryip queryport qname qtype"
  text-format-delimiter: ";"
```


## Jinja inline


If you want a more flexible format, you can use the `text-jinja` setting
Example to enable output similiar to dig style:

```
text-jinja: |+
    ;; Got {% if dm.DNS.Type == "QUERY" %}query{% else %}answer{% endif %} from {{ dm.NetworkInfo.QueryIP }}#{{ dm.NetworkInfo.QueryPort }}:
    ;; ->>HEADER<<- opcode: {{ dm.DNS.Opcode }}, status: {{ dm.DNS.Rcode }}, id: {{ dm.DNS.ID }}
    ;; flags: {{ dm.DNS.Flags.QR | yesno:"qr ," }}{{ dm.DNS.Flags.RD | yesno:"rd ," }}{{ dm.DNS.Flags.RA | yesno:"ra ," }}; QUERY: {{ dm.DNS.QdCount }}, ANSWER: {{ dm.DNS.AnCount }}, AUTHORITY: {{ dm.DNS.NsCount }}, ADDITIONAL: {{ dm.DNS.ArCount }}
    
    ;; QUESTION SECTION:
    ;{{ dm.DNS.Qname }}		{{ dm.DNS.Qclass }}	{{ dm.DNS.Qtype }}

    ;; ANSWER SECTION: {% for rr in dm.DNS.DNSRRs.Answers %}
    {{ rr.Name }}		{{ rr.TTL }} {{ rr.Class }} {{ rr.Rdatatype }} {{ rr.Rdata }}{% endfor %}

    ;; WHEN: {{ dm.DNSTap.Timestamp }}
    ;; MSG SIZE  rcvd: {{ dm.DNS.Length }}
```

## JSON encoding


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
    "qdcount": 1,
    "ancount": 1,
    "nscount": 0,
    "arcount": 0,
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
  "dns.qdcount": 0,
  "dns.ancount": 1,
  "dns.arcount": 0,
  "dns.nscount": 0,
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

### Extended JSON format

This JSON message can be extended by collector(s):

- [PowerDNS collector](collectors/collector_powerdns.md)

This JSON message can be also extended by transformer(s):

- [Atags](transformers/transformer_atags.md)
- [GeoIP](transformers/transformer_geoip.md)
- [Suspicious traffic detector](transformers/transform_suspiciousdetector.md)
- [Public suffix](transformers/transform_normalize.md)
- [Traffic reducer](transformers/transform_trafficreducer.md)
- [Traffic filtering](transformers/transformer_trafficfiltering.md)

## Save to PCAP files

In PCAP mode, DNS traffic is logged in binary form, capturing details over various protocols. The following mappings are used:

| Origin protocol        | Translated to                  |
| -----------------------|--------------------------------|
| DNS/53 over UDP        | DNS UDP/53                     |
| DNS/53 over TCP        | DNS TCP/53                     |
| DoH/443                | DNS UDP/443 (no cipher)        |
| DoT/853                | DNS UDP/853 (no cipher)        |
| DoQ                    | Currently unsupported          |

## Save to DNStap files

todo
