# go-dnscollector

`go-dnscollector` acts as a high speed passive analyser for DNS traffic.

Features:
- Support for [Dnstap](https://dnstap.info/) (TCP, Unix) receiver
- Prometheus metrics support
- Written in Go

## From binary

```go
./go-dnscollector -config config.yml
```

## Configuration

See [config](https://github.com/dmachard/go-dnscollector/blob/main/config.yml) file.

![overview](doc/overview.svg)

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
