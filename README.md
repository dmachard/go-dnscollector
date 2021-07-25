# go-dnscollector

`go-dnscollector` acts as a high speed passive analyser for DNS traffic.

Features:
- Support for [Dnstap](https://dnstap.info/) (TCP, Unix) collector
- Support for [Dnstap](https://dnstap.info/) (TCP) generator
- Support for dns log files generator
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

See [config](https://github.com/dmachard/go-dnscollector/blob/main/config.yml) file.

## Metrics

```
curl http://127.0.0.1:8080/metrics
```

## Top domains

```
curl http://127.0.0.1:8080/tables/domains
```

## Top clients

```
curl http://127.0.0.1:8080/tables/clients
```

## Top rcodes

```
curl http://127.0.0.1:8080/tables/rcodes
```

## Top operations

```
curl http://127.0.0.1:8080/tables/operations
```

## Top rrtypes

```
curl http://127.0.0.1:8080/tables/rrtypes
```
