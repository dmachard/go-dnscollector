<p align="center">
[![Go Report Card](https://goreportcard.com/badge/github.com/dmachard/go-dns-collector)](https://goreportcard.com/report/dmachard/go-dns-collector)
![Go version](https://img.shields.io/badge/go%20version-min%201.20-blue)
![Go tests](https://img.shields.io/badge/go%20tests-377-green)
![Go lines](https://img.shields.io/badge/go%20lines-36222-red)

![Go Tests](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-go.yml/badge.svg)
![Github Actions](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-dnstap.yml/badge.svg)
![Github Actions PDNS](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-powerdns.yml/badge.svg)
</p>

<p align="center">
<img src="docs/dns-collector_logo.png" alt="DNS-collector"/>
</p>

`DNS-collector` acts as a passive high speed **ingestor** with **pipelining** support for your DNS logs, written in **Golang**. It allows enhancing your DNS logs by adding metadata, extracting usage patterns, and facilitating security analysis. The DNS traffic can be collected and aggregated from simultaneously [sources](./docs/collectors.md) like DNStap streams, network interface or log files and relays it to multiple other [listeners](./docs/loggers.md) with some [transformations](./docs/transformers.md) on it ([traffic filtering](./docs/transformers.md#dns-filtering), [user privacy](./docs/transformers.md#user-privacy), ...).

> Additionally, DNS-collector also support
>
> - DNS protocol conversions (to [plain text](https://github.com/dmachard/go-dns-collector/blob/main/docs/configuration.md#custom-text-format), [JSON](https://github.com/dmachard/go-dns-collector/blob/main/docs/dnsjson.md), and more... )
> - DNS parser with [Extension Mechanisms for DNS (EDNS)](https://github.com/dmachard/go-dns-collector/blob/main/docs/dnsparser.md) support
> - IPv4/v6 defragmentation and TCP reassembly
> - Nanoseconds in timestamps

## Features

*NOTE: The code before version 1.x is considered beta quality and is subject to breaking changes.*

- **[Pipelining](./docs/running_mode.md)**

  [![overview](./docs/_images/overview.png)](./docs/running_mode.md)

- **[Collectors](./docs/collectors.md)**

  - *Listen for logging traffic with streaming network protocols*
    - [`DNStap`](docs/collectors/collector_dnstap.md#dns-tap) with `tls`|`tcp`|`unix` transports support and [`proxifier`](docs/collectors/collector_dnstap.md#dns-tap-proxifier)
    - [`PowerDNS`](docs/collectors/collector_powerdns.md) streams with full  support
    - [`TZSP`](docs/collectors/collector_tzsp.md) protocol support
  - *Live capture on a network interface*
    - [`AF_PACKET`](docs/collectors/collector_afpacket.md) socket with BPF filter
    - [`eBPF XDP`](docs/collectors/collector_xdp.md) ingress traffic
  - *Read text or binary files as input*
    - Read and tail on [`Plain text`](docs/collectors/collector_tail.md) files
    - Ingest [`PCAP`](docs/collectors/collector_fileingestor.md) or [`DNSTap`](docs/collectors/collector_fileingestor.md) files by watching a directory

- **[Loggers](./docs/loggers.md)**

  - *Local storage of your DNS logs in text or binary formats*
    - [`Stdout`](docs/loggers/logger_stdout.md) console in text or binary output
    - [`File`](docs/loggers/logger_file.md) with automatic rotation and compression
  - *Provide metrics and API*
    - [`Prometheus`](docs/loggers/logger_prometheus.md) metrics
    - [`Statsd`](docs/loggers/logger_statsd.md) support
    - [`REST API`](docs/loggers/logger_restapi.md) with [swagger](https://generator.swagger.io/?url=https://raw.githubusercontent.com/dmachard/go-dnscollector/main/docs/swagger.yml) to search DNS domains
  - *Send to remote host with generic transport protocol*
    - [`TCP`](docs/loggers/logger_tcp.md)
    - [`Syslog`](docs/loggers/logger_syslog.md) with TLS support
    - [`DNSTap`](docs/loggers/logger_dnstap.md) protobuf messages with TLS support
  - *Send to various sinks*
    - [`Fluentd`](docs/loggers/logger_fluentd.md)
    - [`InfluxDB`](docs/loggers/logger_influxdb.md)
    - [`Loki`](docs/loggers/logger_loki.md)
    - [`ElasticSearch`](docs/loggers/logger_elasticsearch.md)
    - [`Scalyr`](docs/loggers/logger_scalyr.md)
    - [`Redis`](docs/loggers/logger_redis.md)
    - [`Kafka`](docs/loggers/logger_kafka.md)
  - *Send to security tools*
    - [`Falco`](docs/loggers/logger_falco.md)

- **[Transformers](./docs/transformers.md)**

  - Traffic [Filtering](docs/transformers/transform_trafficfiltering.md) and [Reducer](docs/transformers/transform_trafficreducer.md)
  - Latency [Computing](docs/transformers/transform_latency.md)
  - Apply [User Privacy](docs/transformers/transform_userprivacy.md)
  - [Normalize](docs/transformers/transform_normalize.md) DNS messages
  - Add [Geographical](docs/transformers/transform_geoip.md) metadata
  - Various data [Extractor](docs/transformers/transform_dataextractor.md)
  - Suspicious traffic [Detector](docs/transformers/transform_suspiciousdetector.md) and [Prediction](docs/transformers/transform_trafficprediction.md)

## Get Started

Download the latest [`release`](https://github.com/dmachard/go-dns-collector/releases) binary and start the DNS-collector with the provided configuration file. The default configuration listens on `tcp/6000` for a DNSTap stream and DNS logs are printed on standard output.

```bash
./go-dnscollector -config config.yml
```

![run](docs/_images/terminal.gif)

If you prefer run it from docker, follow this [guide](./docs/docker.md).

## Configuration

The configuration of DNS-collector is done through a file named [`config.yml`](config.yml). When the DNS-collector starts, it will look for the config.yml from the current working directory.

See the full [configuration guide](./docs/configuration.md) for more details.

Run the DNS-collector in dry mode to verify the configuration.

```bash
./go-dnscollector -config config.yml -test-config
INFO: 2023/12/24 14:43:29.043730 main - config OK!
```

## Usage examples

The [`_examples`](./docs/_examples) folder from documentation contains a number of [various configurations](./docs/examples.md) to get you started with the DNS-collector in differentes ways.

## Contributing

See the [development guide](./docs/development.md) for more information on how to build it yourself.
