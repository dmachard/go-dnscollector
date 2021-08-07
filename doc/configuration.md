# DnsCollector Configuration Guide

See [config](https://github.com/dmachard/go-dnscollector/blob/main/config.yml) file.

- [Collectors](#Collectors)
  - [Dnstap TCP](#Dnstap-TCP)
  - [Dnstap Unix](#Dnstap-Unix)
  - [Sniffer](#Sniffer)
- [Generators](#Generators)
  - [Stdout](#Stdout)
  - [Build-in Webserver](#Build-in-Webserver)
  - [Log File](#Log-File)
  - [Dnstap TCP](#Dnstap-TCP-Generator)
  - [Dnstap Unix](#Dnstap-Unix-Generator)
  - [JSON TCP](#JSON-TCP)

## Collectors

### DNStap TCP

Dnstap TCP stream collector.

```yaml
dnstap-tcp:
  enable: true
  listen-ip: 0.0.0.0
  listen-port: 6000
```

### DNStap Unix

Similar to the previous one, but uses a unix socket instead of a tcp socket.

```yaml
dnstap-unix:
  enable: false
  sock-path: null
```

### Sniffer

Raw DNS packets sniffer

```yaml
dnstap-unix:
  enable: false
  sock-path: null
```

## Generators

### Stdout

Print to your standard output, all DNS logs received in text or json format

```yaml
stdout:
  enable: false
  mode: text
```

Example:

Text

```
2021-08-07T15:33:15.168298439Z dnscollector CLIENT_QUERY NOERROR 10.0.0.210 32918 INET UDP 54b www.google.fr A 0.000000
2021-08-07T15:33:15.457492773Z dnscollector CLIENT_RESPONSE NOERROR 10.0.0.210 32918 INET UDP 152b www.google.fr A 0.28919
```

JSON

```json
{
  "operation": "CLIENT_RESPONSE",
  "identiy": "dnscollector",
  "family": "INET",
  "protocol": "UDP",
  "query-ip": "10.0.0.51",
  "query-port": "47789",
  "response-ip": "10.0.0.2",
  "response-port": "53",
  "length": 60,
  "rcode": "NOERROR",
  "qname": "play.google.com",
  "qtype": "A",
  "latency": "0.004502",
  "timestamp-rfc3339": "2021-08-07T15:31:56.572064655Z",
  "answers": [
    {
      "name": "play.google.com",
      "rdatatype": "A",
      "ttl": 0,
      "rdata": "142.250.185.110"
    }
  ]
}
```

### Build-in Webserver

Build-in webserver to retrieve somes statistics like top domains, clients and more...
Basic authentication supported.

```yaml
webserver:
  enable: true
  listen-ip: 0.0.0.0
  listen-port: 8080
  top-max-items: 100
  basic-auth-login: admin
  basic-auth-pwd: changeme
```


### Log File

Enable this generator if you want to log to a file.

```yaml
logfile:
  enable: false
  file-path: null
  max-size: 100
  max-files: 10
  log-queries: true
  log-replies: true
```

### DNStap TCP Generator

DNStap tcp stream generator to a remote destination.

```yaml
dnstap-tcp:
  enable: false
  remote-ip: 10.0.0.1
  remote-port: 6000
  retry: 5
  dnstap-identity: dnscollector
```

### DNStap Unix Generator

Same the previous one but uses a unix socket instead of a tcp socket

```yaml
dnstap-unix:
  enable: false
  sock-path: null
  retry: 5
  dnstap-identity: dnscollector
```

### JSON tcp

```yaml
json-tcp:
  enable: true
  remote-ip: 127.0.0.1
  remote-port: 9999
  retry-interval: 5
```

Example:

```json
{
  "operation": "AUTH_RESPONSE",
  "identiy": "dnstap-generator",
  "family": "INET",
  "protocol": "DOH",
  "query-ip": "127.0.126.114",
  "query-port": "42978",
  "response-ip": "127.0.240.58",
  "response-port": "53",
  "length": 160,
  "rcode": "NOERROR",
  "qname": "mondomaine.fr",
  "qtype": "A",
  "latency": "0.000011",
  "timestamp-rfc3339": "2021-07-31T18:16:46.068840539Z",
  "resource-records": [
    {
      "name": "mondomaine.fr",
      "rdatatype": "A",
      "ttl": 3600,
      "rdata": "127.0.0.1"
    }
  ]
}
```
