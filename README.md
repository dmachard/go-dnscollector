# DNS-collector

[![Go Report Card](https://goreportcard.com/badge/github.com/dmachard/go-dns-collector)](https://goreportcard.com/report/dmachard/go-dns-collector)
![Go Tests](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-go.yml/badge.svg)
![Github Actions](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-dnstap.yml/badge.svg)
![Github Actions PDNS](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-powerdns.yml/badge.svg)

*NOTE: The code before version 1.x is considered beta quality and is subject to breaking changes.*

`DNS-collector` acts as a passive high speed **aggregator, analyzer, transporter and logging** for your DNS messages, written in **Golang**. The DNS traffic can be collected and aggregated from simultaneously sources like DNStap streams, network interface or log files
and redirect them to several destinations with some transformations on it (filtering, sampling, privacy, ...).
DNS-collector also contains DNS parser with [`EDNS`](doc/dnsparser.md) support.

![overview](doc/overview.png)

**Supported collectors**:
- *Listen for logging traffic with streaming network protocols*
    - Protobuf [`DNStap`](doc/collectors.md#dns-tap) with tcp or unix support
    - Protobuf [`PowerDNS`](doc/collectors.md#protobuf-powerdns) streams
- *Live capture on a network interface*   
    - [`AF_PACKET`](doc/collectors.md#dns-sniffer) socket with BPF filter
- *Read text or binary files as input*
    - Read and tail on [`Log file`](doc/collectors.md#tail)
    - Ingest [`PCAP files`](doc/collectors.md#ingest-pcap) by watching a directory

**Supported loggers**:
- *Redirect DNS logs to stdout or file in plain text or binary mode*:
    - Print directly to your [`Stdout`](doc/loggers.md#stdout) console
    - Write to [`File`](doc/loggers.md#log-file) with custom [text](doc/configuration.md#custom-text-format) format
    - Write to [`File`](doc/loggers.md#log-file) with [JSON](doc/dnsjson.md) format
    - Write to binary [`Pcap`](doc/loggers.md#log-file) file

- *Provide metrics and API*:
    - [`Prometheus`](doc/loggers.md#prometheus) metrics and visualize-it with built-in [dashboards](doc/dashboards.md) for Grafana
    - [`Statsd`](doc/loggers.md#statsd-client) support
    - [`REST API`](doc/loggers.md#rest-api) with [swagger](https://generator.swagger.io/?url=https://raw.githubusercontent.com/dmachard/go-dnscollector/main/doc/swagger.yml) to search DNS domains
- *Send to remote host with generic protocol*:
    - [`TCP`](doc/loggers.md#tcp-client)
    - [`Syslog`](doc/loggers.md#syslog)
    - [`DNSTap`](doc/loggers.md#dnstap-client) protobuf messages
- *Send to various sinks*:
    - [`Fluentd`](doc/loggers.md#fluentd-client)
    - [`InfluxDB`](doc/loggers.md#influxdb-client)
    - [`Loki`](doc/loggers.md#loki-client)
    - [`ElasticSearch`](doc/loggers.md#elasticsearch-client)

## Get Started

Download the latest [`release`](https://github.com/dmachard/go-dns-collector/releases) binary and start the DNS-collector with the provided configuration file. The default configuration listens on `tcp/6000` for a DNSTap stream and DNS logs are printed on standard output.

```go
./go-dnscollector -config config.yml
```

If you prefer run it from docker, follow this [guide](doc/docker.md).

## Configuration

The configuration of DNS-collector is done through a file named [`config.yml`](config.yml). When the DNS-collector starts, it will look for the config.yml from the current working directory. 

See the full [configuration guide](doc/configuration.md) for more details.

## Examples:

You will find below some examples of configuration to manage your DNS logs.

- [Capture DNSTap stream and backup-it to text and pcap files](example-config/use-case-1.yml)
- [Observe DNS metrics with Prometheus and Grafana](example-config/use-case-2.yml)
- [Transform DNSTap to JSON format](example-config/use-case-3.yml)
- [Follow DNS traffic with Loki and Grafana](example-config/use-case-4.yml)
- [Read from UNIX DNSTap socket and forward it to TLS stream](example-config/use-case-5.yml)
- [Capture DNSTap stream and apply user privacy on it](example-config/use-case-6.yml)
- [Aggregate several DNSTap stream and forward it to the same file](example-config/use-case-7.yml)
- [PowerDNS collector with prometheus metrics](example-config/use-case-8.yml)
- [Filtering incoming traffic with downsample and whitelist of domains](example-config/use-case-9.yml)
- [Transform all domains to lowercase](example-config/use-case-10.yml)
- [Add geographical metadata with GeoIP](example-config/use-case-11.yml)

## Contributing

See the [development guide](doc/development.md) for more information on how to build it yourself.
