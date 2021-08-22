# go-dnscollector

`go-dnscollector` acts as a high speed passive analyser for DNS traffic written in Go.

Features:
- Collectors 
    - Streams [Dnstap](https://dnstap.info/)
        * tcp or unix socket listener with tls support
    - DNS packets sniffer
        * IPv4, IPv6 support (fragmented packet ignored)
        * UDP and TCP transport
        * BFP filtering
- Loggers
    - To Stdout
        * supported format: text, json
    - Log files
        * with rotation file support
        * supported format: text
    - [Dnstap](https://dnstap.info/) stream client
        * to remote tcp destination or unix socket with tls support
    - Raw TCP client
        * to remote tcp destination or unix socket with tls support
        * supported format: text, json
    - Rest API Web server with prometheus metrics and DNS usage support 
        * qps, total queries/replies, top domains, clients, rcodes...
        * basic auth and tls support
    - Syslog server
        * local or remote one
    - [Fluentd](https://www.fluentd.org/) client
        * to remote fluentd collector or unix socket with tls support
        * [msgpask](https://msgpack.org/)
    - [Pcap](https://en.wikipedia.org/wiki/Pcap) files
        * with rotation file support
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