# DNS 

[![Go Report Card](https://goreportcard.com/badge/github.com/dmachard/go-dns-collector)](https://goreportcard.com/report/dmachard/go-dns-collector)
![Go Tests](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-go.yml/badge.svg)
![Github Actions](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-dnstap.yml/badge.svg)
![Github Actions PDNS](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-powerdns.yml/badge.svg)

*NOTE: The code before version 1.x is considered beta quality and is subject to breaking changes.*

`DNS-collector` acts as a high speed **aggregator, analyzer, transporter and logging**  for your DNS traffic, written in **Golang**. The DNS Traffic can be collected and aggregated simultaneously from many different sources (dnstap, sniffer, logs, etc.) .

![overview](doc/overview.png)

DNS-collector can also help you to visualize DNS traffic errors and anomalies with   dashboard.

![overview](doc/overview2.png)

DNS-collector can be used to transform dns queries or replies in JSON format with EDNS support.
 
 ```js
{
  // query/reply ip and port, tcp/udp protocol and family used
  "network": {...},
  // message type, arrival packet time, latency.
  "dnstap": {...},
  // dns fields
  "dns": {...},
  // extended dns options like csubnet
  "edns": {...},
  // country, continent and city informations
  "geo": {...},
  // specific powerdns metadata like tags, original-request-subnet
  "pdns": {...}
}
```


## Features
- [Logs routing](doc/multiplexer.md)
- [Queries/Replies JSON encoding](doc/dnsjson.md)
- Collectors:
    - [DNStap streams](doc/collectors.md#dns-tap) 
    - [DNS packets sniffer](doc/collectors.md#dns-sniffer)
    - [Tail on log file](doc/collectors.md#tail)
    - [Protobuf PowerDNS](doc/collectors.md#protobuf-powerdns)
- Loggers:
    - [Console](doc/loggers.md#stdout)
    - [Prometheus](doc/loggers.md#prometheus)
    - [File](doc/loggers.md#log-file)
    - [DNStap](doc/loggers.md#dnstap-client)
    - [TCP](doc/loggers.md#tcp-client)
    - [REST API](doc/loggers.md#rest-api)
    - [Syslog](doc/loggers.md#syslog)
    - [Fluentd](doc/loggers.md#fluentd-client)
    - [Pcap](doc/loggers.md#pcap-file)
    - [InfluxDB](doc/loggers.md#influxdb-client)
    - [Loki](doc/loggers.md#loki-client)
    - [Statsd](doc/loggers.md#statsd-client)
    - [ElasticSearch](doc/loggers.md#elasticsearch-client)

- Other features
    - [DNS decoder with extended options support](doc/dnsparser.md)
    - [Built-in Grafana dashboards](doc/dashboards.md)
    - [GeoIP support](doc/configuration.md#geoip-support)
    - [Text format](doc/configuration.md#custom-text-format)
    - [DNS filtering](doc/configuration.md#dns-filtering)
    - [User Privacy](doc/configuration.md#user-privacy)
    - [Normalize Qname](doc/configuration.md#qname-lowercase)

- YAML configuration examples
    - [Capture DNSTap stream and backup-it to text files](https://dmachard.github.io/posts/0034-dnscollector-dnstap-to-log-files/)
    - [Get statistics usage with Prometheus and Grafana](https://dmachard.github.io/posts/0035-dnscollector-grafana-prometheus/)
    - [Log DNSTap to JSON format](https://dmachard.github.io/posts/0042-dnscollector-dnstap-json-answers/)
    - [Follow DNS traffic with Loki and Grafana](https://dmachard.github.io/posts/0044-dnscollector-grafana-loki/)
    - [Forward UNIX DNSTap to TLS stream](example-config/use-case-5.yml)
    - [Capture DNSTap with user privacy options enabled](example-config/use-case-6.yml)
    - [Aggregate several DNSTap stream and forward to the same file](example-config/use-case-7.yml)
    - [Run PowerDNS collector with prometheus metrics](example-config/use-case-8.yml)
    - [Run PowerDNS collector with prometheus metrics](example-config/use-case-8.yml)

## Get started

**Run-it from dockerhub**

Use the `[default configuration](config.yml)` (dnstap -> stdout + rest api):

```bash
docker run -d --name=dnscollector01 dmachard/go-dnscollector
```

Override the default configuration `/etc/dnscollector/config.yml` with a config file on the host:

```bash
-v $(pwd)/config.yml:/etc/dnscollector/config.yml
```

**Run-it from binary**

Download the binary from release page. If you want to integrate this tool with systemd, please to follow this [guide](https://dmachard.github.io/posts/0007-dnscollector-install-binary/).

```go
./go-dnscollector -config config.yml
```

## Configuration

See the full [Configuration guide](doc/configuration.md) for more details.

## Use-cases

As prerequisites, we assume you have a DNS server which supports DNSTap (unbound, bind, powerdns, etc)

For more informations about **dnstap**, please to read the following page [Dnstap: How to enable it on main dns servers](https://dmachard.github.io/posts/0001-dnstap-testing/)

## Benchmark

Tested on the following machine: 8 vCPUs, 32 GB memory

| packet per sec received| DnsCollector |
| ---- | ---- | 
| 50k   | OK - 0% lost| 
| 100k   | OK - 0% lost| 
| 150k   | OK (0.07% lost)|

## Contributing

See the [development guide](doc/development.md) for more information on how to build yourself.
