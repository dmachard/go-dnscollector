# DNS Collector

##  Overview

This `dns collector` acts as a **high speed** passive analyser for DNS traffic written in **Golang** which give you the possibility to control dns servers, get statistics and more. It supports several methods as input to collect dns traffic (dnstap, sniffer, logs, etc.) and can redirect them to multiple destinations with transformation to text or json format. This collector can also be used to logs dns answers.

![overview](doc/overview.png)

Some Grafana dashboards are also available:

![overview](doc/dashboard1.png)

NOTE: The code before version 1.x is considered beta quality and is subject to breaking changes. 

## Features

- Supported collectors:
    - [Dnstap streams](doc/configuration.md#Dnstap) 
    - DNS packets sniffer
    - Tail on log file

- Supported loggers:
    - Stdout
    - Text files
    - [Dnstap](https://dnstap.info/) client
    - Raw TCP client
    - [Rest API](https://generator.swagger.io/?url=https://raw.githubusercontent.com/dmachard/go-dnscollector/main/doc/swagger.yml)
    - [Syslog](https://en.wikipedia.org/wiki/Syslog)
    - [Fluentd](https://www.fluentd.org/)
    - [Pcap](https://en.wikipedia.org/wiki/Pcap)
    - [InfluxDB](https://www.influxdata.com/) (experimental)
    - [Loki](https://grafana.com/oss/loki/) (experimental)
    - [Statsd](https://github.com/statsd/statsd) (experimental)

- Other features
    - GeoIP support (Country code)
    - Packet filtering (regex support)
    - Query IP-Addresses anonymizer

## Installation

**Run-it from binary**

Download the binary from release page. If you want to integrate this tool with systemd, please to follow this [guide](https://dmachard.github.io/posts/0007-dnscollector-install-binary/).

```go
./go-dnscollector -config config.yml
```

**Run-it from dockerhub**

Use the default config (dnstap -> stdout + rest api):

```bash
docker run -d --rm --network host --name=dnscollector01 dmachard/go-dnscollector
```

Override the default configuration (/etc/dnscollector/config.yml) with a config file on the host and custom ports:

```bash
-v $(pwd)/config.yml:/etc/dnscollector/config.yml
```

## Configuration

A typically configuration would have one or more collector to receive DNS traffic or logs, and severals loggers to process the 
incoming traffics. See the full [Configuration guide](doc/configuration.md) for more details.

## Use-cases

As prerequisites, we assume you have a DNS server which supports DNSTap (unbound, bind, powerdns, etc)

- [x] [Use case 1: collect dnstap stream and backup-it to text log files](https://dmachard.github.io/posts/0034-dnscollector-dnstap-to-log-files/)
- [x] [Use case 2: collect dnstap stream and get statistics usage with Prometheus + Grafana](https://dmachard.github.io/posts/0035-dnscollector-grafana-prometheus/)
- [x] [Use case 3: collect dnstap stream and log dns answers in JSON format](https://dmachard.github.io/posts/0042-dnscollector-dnstap-json-answers/)
- [x] [Use case 4: collect dnstap stream and follow dns logs with Loki + Grafana](https://dmachard.github.io/posts/0044-dnscollector-grafana-loki/)

For more informations about **dnstap**, please to read the following page [Dnstap: How to enable it on main dns servers](https://dmachard.github.io/posts/0001-dnstap-testing/)


## Metrics

See [Metrics](doc/metrics.txt).

| Metric | Description |
| ---- | ---- | 
| dnscollector_qps   | Number of queries per second received | 
| dnscollector_requesters_total | Number of clients |
| dnscollector_domains_total | Number of domains observed |
| dnscollector_received_bytes_total | Total bytes received |
| dnscollector_sent_bytes_total | Total bytes sent |

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
