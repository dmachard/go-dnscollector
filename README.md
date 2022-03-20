# DNS Collector

##  Overview

This `dns collector` acts as a **high speed** passive analyser for DNS traffic, written in Golang. Which give you the possibility to control dns servers, get statistics and more. It supports several methods to collect dns traffic (dnstap, sniffer, logs, etc.) and can redirect them to multiple destinations with protocol and format (json, text) transformation. This collector can also be used to logs dns answers.

![overview](doc/overview.png)

NOTE: The code before version 1.x is considered beta quality and is subject to breaking changes. 

## Features

- Supported collectors:
    - [DNStap streams](doc/configuration.md#dns-tap) 
    - [DNS packets sniffer](doc/configuration.md#Dns-Sniffer)
    - [Tail on log file](doc/configuration.md#tail)
    - [Protobuf PowerDNS](doc/configuration.md#protobuf-powerdns)

- Supported loggers:
    - [Stdout](doc/configuration.md#stdout)
    - [File](doc/configuration.md#log-file)
    - [DNStap](doc/configuration.md#dnstap-client)
    - [TCP](doc/configuration.md#tcp-client)
    - [Prometheus](doc/configuration.md#rest-api)
    - [Syslog](doc/configuration.md#syslog)
    - [Fluentd](doc/configuration.md#fluentd-client)
    - [Pcap](doc/configuration.md#pcap-file)
    - [InfluxDB](doc/configuration.md#influxdb-client)
    - [Loki](doc/configuration.md#loki-client)
    - [Statsd](doc/configuration.md#statsd-client)

- Other features
    - [Queries/Replies JSON encoding](doc/dnsjson.md)
    - [DNS decoder with extended options support](doc/dnsparser.md)
    - [Built-in Grafana dashboards](doc/dashboards.md)
    - [GeoIP support](doc/configuration.md#geoip-support)
    - [Log filtering](doc/configuration.md#log-filtering)
    - [User Privacy](doc/configuration.md#user-privacy)
    - [Custom text format](doc/configuration.md#custom-text-format)
    - [DNS caching](doc/configuration.md#DNS-Caching)
    - [Normalize Qname](doc/configuration.md#Qname-lowercase)

## End to end testing

Tested with success with the following dns servers

![unbound 1.15.x](https://img.shields.io/badge/unbound%201.15.x-tested-green)

![powerdns dnsdist 1.6.x](https://img.shields.io/badge/dnsdist%201.6.x-tested-green)
![powerdns dnsdist 1.7.x](https://img.shields.io/badge/dnsdist%201.7.x-tested-green)

![coredns 1.8.7](https://img.shields.io/badge/coredns%201.8.7-tested-green)
![coredns 1.9.0](https://img.shields.io/badge/coredns%201.9.0-tested-green)

## Installation

**Run-it from binary**

Download the binary from release page. If you want to integrate this tool with systemd, please to follow this [guide](https://dmachard.github.io/posts/0007-dnscollector-install-binary/).

```go
./go-dnscollector -config config.yml
```

**Run-it from dockerhub**

Use the default config (dnstap -> stdout + rest api):

```bash
docker run -d --name=dnscollector01 dmachard/go-dnscollector
```

Override the default configuration (/etc/dnscollector/config.yml) with a config file on the host:

```bash
-v $(pwd)/config.yml:/etc/dnscollector/config.yml
```

## Configuration

See the full [Configuration guide](doc/configuration.md) for more details.

## Use-cases

As prerequisites, we assume you have a DNS server which supports DNSTap (unbound, bind, powerdns, etc)

For more informations about **dnstap**, please to read the following page [Dnstap: How to enable it on main dns servers](https://dmachard.github.io/posts/0001-dnstap-testing/)

- [x] [Use case 1: Capture dns traffic (dnstap) and backup-it to text log files](https://dmachard.github.io/posts/0034-dnscollector-dnstap-to-log-files/)
- [x] [Use case 2: Capture dns traffic (dnstap) and get statistics usage with Prometheus + Grafana](https://dmachard.github.io/posts/0035-dnscollector-grafana-prometheus/)
- [x] [Use case 3: Convert captured dns traffic (dnstap) to JSON format](https://dmachard.github.io/posts/0042-dnscollector-dnstap-json-answers/)
- [x] [Use case 4: Capture dns traffic (dnstap) and follow dns logs with Loki + Grafana](https://dmachard.github.io/posts/0044-dnscollector-grafana-loki/)
- [x] [Use case 5: Forward unix dnstap socket traffic to TLS dnstap stream](example-config/use-case-5.yml)
- [x] [Use case 6: Capture dns traffic with user privacy options enabled](example-config/use-case-6.yml)

## Benchmark

Tested on the following machine: 8 vCPUs, 32 GB memory

| packet per sec received| DnsCollector |
| ---- | ---- | 
| 50k   | OK - 0% lost| 
| 100k   | OK - 0% lost| 
| 150k   | OK (0.07% lost)|

## For developers

Run from source 

```
go run .
```

Execute testunits

```
go test -timeout 10s ./collectors/ -cover -v
go test -timeout 10s ./loggers/ -cover -v
go test -timeout 10s ./subprocessors/ -cover -v
```

Execute a test for one specific testcase in a package

```
go test -timeout 10s -cover -v ./loggers -run TestSyslogRunJsonMode
```

Building from source. Use the latest golang available on your target system 
```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o go-dnscollector *.go
```
