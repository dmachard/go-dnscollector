# go-dnscollector

`go-dnscollector` acts as a high speed passive analyser for DNS traffic written in Go.

Features:
- Collectors 
    - [Dnstap](https://dnstap.info/) Streams
        * tcp or unix socket listener with tls support
    - DNS packets sniffer
        * IPv4, IPv6 support (fragmented packet ignored)
        * UDP and TCP transport
        * BFP filtering
- Loggers
    - Stdout
        * supported format: text, json
    - Text files
        * with rotation file support
        * supported format: text
    - [Dnstap](https://dnstap.info/) stream client
        * to remote tcp destination or unix socket with tls support
    - Raw TCP client
        * to remote tcp destination or unix socket with tls support
        * supported format: text, json
    - [Rest API](https://generator.swagger.io/?url=https://raw.githubusercontent.com/dmachard/go-dnscollector/main/doc/swagger.yml) 
        * prometheus metrics format
        * qps, total queries/replies, top domains, clients, rcodes...
        * basic auth
        * tls support
    - [Syslog](https://en.wikipedia.org/wiki/Syslog) server
        * local or remote one
    - [Fluentd](https://www.fluentd.org/) client
        * to remote fluentd collector or unix socket with tls support
        * [msgpask](https://msgpack.org/)
    - [Pcap](https://en.wikipedia.org/wiki/Pcap) files
        * with rotation file support
        * binary format
- GeoIP support (Country code)
- Packet filtering (regex support)
- Query IP-Addresses anonymizer

![overview](doc/overview.png)

## Installation

Run-it from binary

```go
./go-dnscollector -config config.yml
```

## Configuration

A typically configuration would have one or more collector to receive DNS traffic or logs, and severals loggers to process the 
incoming traffics. See [Configuration guide](doc/configuration.md) file.

## Benchmark

Tested on the following machine: 8 vCPUs, 32 GB memory

| packet per sec received| DnsCollector |
| ---- | ---- | 
| 50k   | OK - 0% lost| 
| 100k   | OK - 0% lost| 
| 150k   | OK (0.07% lost)|