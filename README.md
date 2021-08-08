# go-dnscollector

`go-dnscollector` acts as a high speed passive analyser for DNS traffic.

Features:
- Collectors 
    - Streams [Dnstap](https://dnstap.info/) (TCP, unix) 
    - DNS packets sniffer (IPv4 and IPv6 support)
- Generators
    - Stream [Dnstap](https://dnstap.info/) (TCP, unix)
    - Plain text or JSON to stdout
    - Plain text to log files
    - JSON to tcp remote destination
    - Web server with prometheus metrics and usage support (qps, total queries/replies, top domains, clients, rcodes...) 
- Written in Go

![overview](doc/overview.png)

## Installation

Run-it from binary

```go
./go-dnscollector -config config.yml
```

## Configuration

A typically configuration would have one or more collector to receive DNS traffic or logs, and severals generetors to process the 
incoming traffics. See [Configuration guide](doc/configuration.md) file.