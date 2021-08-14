# go-dnslogger

`go-dnslogger` acts as a high speed passive analyser for DNS traffic written in Go

Features:
- Collectors 
    - Streams [Dnstap](https://dnstap.info/) (tcp, unix transport) 
    - DNS packets sniffer (IPv4 and IPv6 support)
    - GeoIP support (Country code)
    - Qname filtering (regex support)
- Loggers
    - Stream [Dnstap](https://dnstap.info/) (tcp, unix transport)
    - Plain text or JSON to stdout
    - Plain text to log files
    - JSON to tcp remote destination
    - Web server with prometheus metrics and usage support (qps, total queries/replies, top domains, clients, rcodes...) 
    - Syslog server (local or remote)

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