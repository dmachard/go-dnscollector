# DNS-collector

[![Go Report Card](https://goreportcard.com/badge/github.com/dmachard/go-dns-collector)](https://goreportcard.com/report/dmachard/go-dns-collector)
![Go Tests](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-go.yml/badge.svg)
![Github Actions](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-dnstap.yml/badge.svg)
![Github Actions PDNS](https://github.com/dmachard/go-dns-collector/actions/workflows/testing-powerdns.yml/badge.svg)

*NOTE: The code before version 1.x is considered beta quality and is subject to breaking changes.*

`DNS-collector` acts as a passive high speed **aggregator, analyzer, transporter and logging** for your DNS messages, written in **Golang**. The DNS traffic can be collected and aggregated from simultaneously sources like DNStap streams, network interface or log files.

![overview](doc/overview.png)

**Supported collectors**:
- Listen traffic coming from [`DNStap streams`](doc/collectors.md#dns-tap)
- [`Sniff traffic`](doc/collectors.md#dns-sniffer) from network interfaces
- Read and tail on [`Log file`](doc/collectors.md#tail)
- Listen for [`Protobuf PowerDNS`](doc/collectors.md#protobuf-powerdns) streams

**Supported loggers**:
- *Write DNS logs to stdout or file with [`Text`](doc/configuration.md#custom-text-format) or [`JSON`](doc/dnsjson.md) format*:
    - [`Stdout`](doc/loggers.md#stdout)console
    - [`Text file`](doc/loggers.md#log-file) with rotation and compression support
    - Binary [`Pcap file`](doc/loggers.md#pcap-file)
- *Provide metrics and API*:
    - [`Prometheus`](doc/loggers.md#prometheus) metrics and visualize-it with built-in [dashboards](doc/dashboards.md) for Grafana
    - [`Statsd`](doc/loggers.md#statsd-client) support
    - [`REST API`](doc/loggers.md#rest-api) to search DNS messages
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

Download the latest [release](https://github.com/dmachard/go-dns-collector/releases) binary and start `DNS-collector` with the provided configuration file. The default configuration listens on `tcp/6000` for an incoming DNSTap stream  and redirects it to the standard output.

```go
./go-dnscollector -config config.yml
```


## Docker

Docker run with a custom configuration:

```bash
docker run -d dmachard/go-dnscollector -v $(pwd)/config.yml:/etc/dnscollector/config.yml
```

## Configuration


DNS-collector is also able to:
- [`Route`](doc/multiplexer.md) DNS messages between collectors and loggers
- Encode DNS messages to [`JSON`](doc/dnsjson.md) or [`Text`](doc/configuration.md#custom-text-format) format. [`EDNS`](doc/dnsparser.md) options is also supported.
- Add geographical metadata with [`GeoIP`](doc/configuration.md#geoip-support)
- [`Filter`](doc/configuration.md#dns-filtering) (drop, downsample...) incoming traffic
- Support [`User Privacy`](doc/configuration.md#user-privacy)
- [`Normalize`](doc/configuration.md#qname-lowercase) qname to lower case

See the full [Configuration guide](doc/configuration.md) for more details.

## Examples:

You will find below some examples of configuration to manage your DNS logs.

- [Capture DNSTap stream and backup-it to text files](https://dmachard.github.io/posts/0034-dnscollector-dnstap-to-log-files/)
- [Get statistics usage with Prometheus and Grafana](https://dmachard.github.io/posts/0035-dnscollector-grafana-prometheus/)
- [Log DNSTap to JSON format](https://dmachard.github.io/posts/0042-dnscollector-dnstap-json-answers/)
- [Follow DNS traffic with Loki and Grafana](https://dmachard.github.io/posts/0044-dnscollector-grafana-loki/)
- [Forward UNIX DNSTap to TLS stream](example-config/use-case-5.yml)
- [Capture DNSTap with user privacy options enabled](example-config/use-case-6.yml)
- [Aggregate several DNSTap stream and forward to the same file](example-config/use-case-7.yml)
- [Run PowerDNS collector with prometheus metrics](example-config/use-case-8.yml)

## Contributing

See the [development guide](doc/development.md) for more information on how to build yourself.
