# go-dnscollector

`go-dnscollector` acts as a high speed passive analyser for DNS traffic.

Features:
- DNS logs collector from [Dnstap](https://dnstap.info/) (TCP, unix) streams
- Stream generator to [Dnstap](https://dnstap.info/) (TCP, unix)
- Log files generator to plain text
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