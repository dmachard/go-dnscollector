# DnsCollector - Loggers Guide

- [Console](#stdout)
- [Prometheus](#prometheus)
- [REST API](#rest-api)
- [Log File](#log-file)
- [DNStap](#dnstap-client)
- [TCP](#tcp-client)
- [Syslog](#syslog)
- [Fluentd](#fluentd-client)
- [Pcap File](#pcap-file)
- [InfluxDB](#influxdb-client)
- [Loki](#loki-client)
- [Statsd](#statsd-client)
- [ElasticSearch](#elasticsearch-client)

## Loggers

### Stdout

Print to your standard output, all DNS logs received
* in text or json format
* custom text format

Options:
- `mode`: (string) text or json
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format

Default values:

```yaml
stdout:
  mode: text
  text-format: ""
```

Example:

```
2021-08-07T15:33:15.168298439Z dnscollector CQ NOERROR 10.0.0.210 32918 INET UDP 54b www.google.fr A 0.000000
2021-08-07T15:33:15.457492773Z dnscollector CR NOERROR 10.0.0.210 32918 INET UDP 152b www.google.fr A 0.28919
```

### Prometheus

This logger generates **prometheus** metrics. Use the following Grafana [dashboard](https://grafana.com/grafana/dashboards/16630).

Options:
- `listen-ip`: (string) listening IP
- `listen-port`: (integer) listening port
- `tls-support`: (boolean) tls support
- `tls-mutual`: (boolean) mtls authentication
- `tls-min-version`: (string) min tls version, default to 1.2
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file
- `prometheus-suffix`: (string) prometheus suffix
- `top-n`: (string) default number of items on top

Default values:

```yaml
prometheus:
  listen-ip: 0.0.0.0
  listen-port: 8081
  tls-support: false
  tls-mutual: false
  tls-min-version: 1.2
  cert-file: ""
  key-file: ""
  prometheus-prefix: "dnscollector"
  top-n: 10
```

### REST API

Build-in webserver with REST API to retrieve somes statistics like top domains, clients and more...
Basic authentication supported. Prometheus metrics is also available through this API.

* prometheus metrics format
* qps, total queries/replies, top domains, clients, rcodes...
* basic auth
* tls support

See the [swagger](https://generator.swagger.io/?url=https://raw.githubusercontent.com/dmachard/go-dnscollector/main/doc/swagger.yml) documentation.

Options:
- `listen-ip`: (string) listening IP
- `listen-port`: (integer) listening port
- `basic-auth-login`: (string) default login for basic auth
- `basic-auth-pwd`: (string) default password for basic auth
- `tls-support`: (boolean) tls support
- `tls-min-version`: (string) min tls version, default to 1.2
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file
- `top-max-items`: (string) default number of items on top
- `common-qtypes`: (list of string)  expected common qtype list, other will be considered as suspicious
- `threshold-qname-len`: (string) a length greater than this value will be considered as suspicious
- `threshold-packet-len`: (string) a size greater than this value will be considered as suspicious value in bytes
- `threshold-slow`: (string) threshold to set a domain considered as slow, value in second
- `prometheus-suffix`: (string) prometheus suffix

Default values:

```yaml
webserver:
  listen-ip: 0.0.0.0
  listen-port: 8080
  basic-auth-login: admin
  basic-auth-pwd: changeme
  tls-support: true
  tls-min-version: 1.2
  cert-file: "./testsdata/server.crt"
  key-file: "./testsdata/server.key"
  top-max-items: 100
  common-qtypes:
    - A
    - AAAA
    - CNAME
    - TXT
    - PTR
    - NAPTR
    - DNSKEY
    - SRV
  threshold-qname-len: 80
  threshold-packet-len: 1000
  threshold-slow: 0.5
  prometheus-suffix: "dnscollector"
```

**Prometheus metrics example:**

Request:

```
$ curl --user admin:changeme http://127.0.0.1:8080/metrics
```

The `<promdsuffix>` tag can be configured in the `config.yml` file.

Metrics list:
- `<promdsuffix>_qps`: Number of queries per second received
- `<promdsuffix>_requesters_total`: Number of clients
- `<promdsuffix>_domains_total`: Number of domains observed
- `<promdsuffix>_received_bytes_total`: Total bytes received
- `<promdsuffix>_sent_bytes_total`: Total bytes sent


The full metrics can be found [here](doc/metrics.txt).


### Log File

Enable this logger if you want to log to a file.
* with rotation file support
* supported format: text, json
* gzip compression
* execute external command after each rotation
* custom text format

Options:
- `file-path`: (string) output logfile name
- `max-size`: (integer) maximum size in megabytes of the file before rotation, A minimum of max-size*max-files megabytes of space disk must be available
- `max-files`: (integer) maximum number of files to retain. Set to zero if you want to disable this feature
- `flush-interval`: (integer) flush buffer to log file every X seconds
- `compress`: (boolean) compress log file
- `compress-interval`: (integer) checking every X seconds if new log files must be compressed
- `compress-command`: (string) run external script after file compress step
- `mode`: (string)  output format: text|json
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `postrotate-command`: (string) run external script after file rotation
- `postrotate-delete-success`: (boolean) delete file on script success

Default values:

```yaml
logfile:
  file-path: null
  max-size: 100
  max-files: 10
  flush-interval: 10
  compress: false
  compress-interval: 5
  compress-command: null
  mode: text
  text-format: ""
  postrotate-command: null
  postrotate-delete-success: false
```

Basic example to use the postrotate command:

Configure the script to execute after each file rotation, for each call the file is passed as argument.

```
logfile:
  postrotate-command: "/home/dnscollector/postrotate.sh"
```

Script to move the log file to a specific folder

```bash
#!/bin/bash

DNSCOLLECTOR=/var/dnscollector/
BACKUP_FOLDER=$DNSCOLLECTOR/$(date +%Y-%m-%d)
mkdir -p $BACKUP_FOLDER

mv $1 $BACKUP_FOLDER
```

### DNStap Client

DNStap stream logger to a remote tcp destination or unix socket.
* to remote tcp destination or unix socket
* tls support

Options:
- `listen-ip`: (string) remote address
- `listen-port`: (integer) remote tcp port
- `sock-path`: (string) unix socket path
- `retry-interval`: (integer) interval in second between retry reconnect
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `server-id`: server identity

Default values:

```yaml
dnstap:
  remote-address: 10.0.0.1
  remote-port: 6000
  sock-path: null
  retry-interval: 5
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  server-id: "dnscollector"
```

### TCP Client

Tcp/unix stream client logger.
* to remote tcp destination or unix socket
* supported format: text, json
* custom text format
* tls support

Options:
- `transport`: (string) network transport to use: tcp|unix
- `listen-ip`: (string) remote address
- `listen-port`: (integer) remote tcp port
- `sock-path`: (string) unix socket path
- `retry-interval`: (integer) interval in second between retry reconnect
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `mode`: (string)  output format: text|json
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format

Default values:

```yaml
tcpclient:
  transport: tcp
  remote-address: 127.0.0.1
  remote-port: 9999
  sock-path: null
  retry-interval: 5
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  mode: json
  text-format: ""
```

### Syslog

Syslog logger to local syslog system or remote one.
* local or remote server
* custom text format
* supported format: text, json
* tls support

Options:
- `facility`: (string) Set the syslog logging facility
- `transport`: (string) Transport to use to a remote log daemon or local one. local|tcp|udp|unix
- `remote-address`: (string) Remote address host:port
- `mode`: (string) text or json
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2

Default values:

```yaml
syslog:
  severity: INFO
  facility: DAEMON
  transport: local
  remote-address: ""
  text-format: ""
  mode: text
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
```

### Fluentd Client

Fluentd client to remote server or unix socket.
* to remote fluentd collector or unix socket
* [msgpask](https://msgpack.org/)
* tls support

Options:
- `transport`: (string) network transport to use: tcp|unix
- `listen-ip`: (string) remote address
- `listen-port`: (integer) remote tcp port
- `sock-path`: (string) unix socket path
- `retry-interval`: (integer) interval in second between retry reconnect
- `tag`: (string) tag name
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2

Default values:

```yaml
fluentd:
  transport: tcp
  remote-address: 127.0.0.1
  remote-port: 24224
  sock-path: null
  retry-interval: 5
  tag: "dns.collector"
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
```

### Pcap File

Enable this logger if you want to log into a pcap file.
* with rotation file support
* binary format
* gzip compression
* execute external command after each rotation

Options:
- `file-path`: (string) output logfile name
- `max-size`: (integer) maximum size in megabytes of the file before rotation
- `max-files`: (integer) maximum number of files to retain.
- `compress`: (boolean) compress pcap file
- `compress-interval`: (integer) checking every X seconds if new log files must be compressed
- `postrotate-command`: (string) run external script after each file rotation
- `postrotate-delete-success`: (boolean) delete file on script success

```yaml
pcapfile:
  file-path: null
  max-size: 1
  max-files: 3
  compress: false
  compress-interval: 5
  postrotate-command: null
  postrotate-delete-success: true
```

### InfluxDB client

InfluxDB client to remote InfluxDB server

Options:
- `server-url`: (string) InfluxDB server url
- `auth-token`: (string) authentication token
- `bucket`: (string) bucket name
- `organization`: (string) organization name
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version

Default values:

```yaml
influxdb:
  server-url: "http://localhost:8086"
  auth-token: ""
  bucket: "db_dns"
  organization: "dnscollector"
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
```

### Loki client

Loki client to remote server

Options:
- `server-url`: (string) Loki server url
- `job-name`: (string) Job name
- `mode`: (string) text or json
- `flush-interval`: (integer) flush batch every X seconds
- `batch-size`: (integer) batch size for log entries in bytes
- `retry-interval`: (integer) interval in second between before to retry to send batch
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `proxy-url`: (string) Proxy URL
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version
- `basic-auth-login`: (string) basic auth login
- `basic-auth-pwd`: (string) basic auth password
- `tenant-id`: (string) tenant/organisation id. If omitted or empty, no X-Scope-OrgID header is sent.

Default values:

```yaml
lokiclient:
  server-url: "http://localhost:3100/loki/api/v1/push"
  job-name: "dnscollector"
  mode: "text"
  flush-interval: 5
  batch-size: 1048576
  retry-interval: 10
  text-format: "localtime identity qr queryip family protocol qname qtype rcode"
  proxy-url: ""
  tls-insecure: false
  tls-min-version: 1.2
  basic-auth-login: ""
  basic-auth-pwd: ""
  tenant-id: ""
```

### Statsd client

Statsd client to statsd proxy
* tls support

**Statsd metrics:**

The `<statsdsuffix>` tag can be configured in the `config.yml` file.

Counters:

```
- <statsdsuffix>_<streamid>_total_bytes_received
- <statsdsuffix>_<streamid>_total_bytes_sent
- <statsdsuffix>_<streamid>_total_requesters
- <statsdsuffix>_<streamid>_total_domains
- <statsdsuffix>_<streamid>_total_domains_nx
- <statsdsuffix>_<streamid>_total_packets
- <statsdsuffix>_<streamid>_total_packets_[udp|tcp]
- <statsdsuffix>_<streamid>_total_packets_[inet|inet6]
- <statsdsuffix>_<streamid>_total_replies_rrtype_[A|AAAA|TXT|...]
- <statsdsuffix>_<streamid>_total_replies_rcode_[NOERROR|SERVFAIL|...]
```

Gauges:

```
- <statsdsuffix>_<streamid>_queries_qps
```

Options:
- `transport`: (string) network transport to use: udp or tcp
- `listen-ip`: (string) remote address
- `listen-port`: (integer) remote tcp port
- `prefix`: (string) statsd prefix name
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version

Default values:

```yaml
statsd:
  transport: udp
  remote-address: 127.0.0.1
  remote-port: 8125
  prefix: "dnscollector"
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
```

### ElasticSearch client

ElasticSearch client to remote ElasticSearch server

Options:
- `url`: (string) Elasticsearch _doc url

```yaml
elasticsearch:
  url: "http://127.0.0.1:9200/indexname/_doc"
```