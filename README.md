# DNS-collector

[![Go Report Card](https://goreportcard.com/badge/github.com/dmachard/go-dns-collector)](https://goreportcard.com/report/dmachard/go-dns-collector)
![Go Tests](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-go.yml/badge.svg)
![Github Actions](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-dnstap.yml/badge.svg)
![Github Actions PDNS](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-powerdns.yml/badge.svg)

*NOTE: The code before version 1.x is considered beta quality and is subject to breaking changes.*

`DNS-collector` acts as a passive high speed **aggregator, analyzer, transporter and logging** for your DNS messages, written in **Golang**. The DNS traffic can be collected and aggregated from simultaneously sources like DNStap streams, network interface or log files.

Currently DNS-collector is able to:
- `Collectors`:
    - Listen traffic coming from [DNStap streams](doc/collectors.md#dns-tap)
    - [Sniff](doc/collectors.md#dns-sniffer) DNS traffic from network interface 
    - Read and tail on [log](doc/collectors.md#tail) file
    - Listen for [Protobuf PowerDNS](doc/collectors.md#protobuf-powerdns) streams
- `Loggers`:
    - Basic:
        - Write DNS logs to the [console](doc/loggers.md#stdout)
        - Provide [REST API](doc/loggers.md#rest-api) to search DNS messages
        - Send [DNSTap](doc/loggers.md#dnstap-client) protobuf messages
    - File:
        - Write to [file](doc/loggers.md#log-file) with rotation and compression support
        - Write to [Pcap](doc/loggers.md#pcap-file) file
    - Metrics:
        - Provide [Prometheus](doc/loggers.md#prometheus) metrics and visualize-it with built-in [dashboards](doc/dashboards.md) for Grafana
        - [Statsd](doc/loggers.md#statsd-client) support
    - Sinks:
        - [Fluentd](doc/loggers.md#fluentd-client)
        - [InfluxDB](doc/loggers.md#influxdb-client)
        - [Loki](doc/loggers.md#loki-client)
        - [ElasticSearch](doc/loggers.md#elasticsearch-client)
        - Generic [TCP](doc/loggers.md#tcp-client) protocol support in text for json format.
        - Remote [Syslog](doc/loggers.md#syslog) server support
- `Other features`:
    - DNS messages [routing](doc/multiplexer.md)
    - Queries/Replies [JSON](doc/dnsjson.md) encoding with  extended options support [EDNS]](doc/dnsparser.md)
    - Add [GeoIP](doc/configuration.md#geoip-support) details
    - Custom [Text](doc/configuration.md#custom-text-format) format
    - [DNS filtering](doc/configuration.md#dns-filtering)
    - [User Privacy](doc/configuration.md#user-privacy)
    - [Normalize Qname](doc/configuration.md#qname-lowercase)

## Installation

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

Download the binary from release page. A default configuration file `config.yml` is also provided.

```go
./go-dnscollector -config config.yml
```

## Configuration

See the full [Configuration guide](doc/configuration.md) for more details.

## Examples:

When starting DNS-collector, you must provide a configuration  file with the `-config` option.

- [Capture DNSTap stream and backup-it to text files](https://dmachard.github.io/posts/0034-dnscollector-dnstap-to-log-files/)
- [Get statistics usage with Prometheus and Grafana](https://dmachard.github.io/posts/0035-dnscollector-grafana-prometheus/)
- [Log DNSTap to JSON format](https://dmachard.github.io/posts/0042-dnscollector-dnstap-json-answers/)
- [Follow DNS traffic with Loki and Grafana](https://dmachard.github.io/posts/0044-dnscollector-grafana-loki/)
- [Forward UNIX DNSTap to TLS stream](example-config/use-case-5.yml)
- [Capture DNSTap with user privacy options enabled](example-config/use-case-6.yml)
- [Aggregate several DNSTap stream and forward to the same file](example-config/use-case-7.yml)
- [Run PowerDNS collector with prometheus metrics](example-config/use-case-8.yml)
- [Run PowerDNS collector with prometheus metrics](example-config/use-case-8.yml)

## Benchmark

Tested on the following machine: 8 vCPUs, 32 GB memory

| packet per sec received| DnsCollector |
| ---- | ---- | 
| 50k   | OK - 0% lost| 
| 100k   | OK - 0% lost| 
| 150k   | OK (0.07% lost)|

## Contributing

See the [development guide](doc/development.md) for more information on how to build yourself.
