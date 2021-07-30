# go-dnscollector

`go-dnscollector` acts as a high speed passive analyser for DNS traffic.

Features:
- Collector for [Dnstap](https://dnstap.info/) (TCP, unix) 
- Generator for [Dnstap](https://dnstap.info/) (TCP, unix) 
- Generator dns log files 
- Prometheus metrics support (qps, total queries/replies...)
- Dns statistics usage support (top domains, clients, rcodes...) 
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