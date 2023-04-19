# DnsCollector - Loggers Guide

- [Console](#stdout)
- [Prometheus](#prometheus)
- [REST API](#rest-api)
- [File](#log-file)
- [DNStap](#dnstap-client)
- [TCP](#tcp-client)
- [Syslog](#syslog)
- [Fluentd](#fluentd-client)
- [InfluxDB](#influxdb-client)
- [Loki](#loki-client)
- [Statsd](#statsd-client)
- [ElasticSearch](#elasticsearch-client)
- [Scalyr](#scalyr-client)
- [Redispub](#redispub)

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
- `basic-auth-login`: (string) default login for basic auth
- `basic-auth-pwd`: (string) default password for basic auth
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
  basic-auth-login: admin
  basic-auth-pwd: changeme
  tls-support: false
  tls-mutual: false
  tls-min-version: 1.2
  cert-file: ""
  key-file: ""
  prometheus-prefix: "dnscollector"
  top-n: 10
```

Scrape metric with curl:

```
$ curl -u admin:changeme http://127.0.0.1:8080/metrics
```

The full metrics can be found [here](doc/metrics.txt).


### REST API

Build-in webserver with REST API to search domains, clients and more...
Basic authentication supported.

See the [swagger](https://generator.swagger.io/?url=https://raw.githubusercontent.com/dmachard/go-dnscollector/main/doc/swagger.yml) documentation.

Options:
- `listen-ip`: (string) listening IP
- `listen-port`: (integer) listening port
- `basic-auth-enable`: (boolean) enable or disable basic authentication
- `basic-auth-login`: (string) default login for basic auth
- `basic-auth-pwd`: (string) default password for basic auth
- `tls-support`: (boolean) tls support
- `tls-min-version`: (string) min tls version, default to 1.2
- `cert-file`: (string) certificate server file
- `key-file`: (string) private key server file
- `top-n`: (string) default number of items on top

Default values:

```yaml
restapi:
  listen-ip: 0.0.0.0
  listen-port: 8080
  basic-auth-enable: true
  basic-auth-login: admin
  basic-auth-pwd: changeme
  tls-support: true
  tls-min-version: 1.2
  cert-file: "./testsdata/server.crt"
  key-file: "./testsdata/server.key"
  top-n: 100
```

### Log File

Enable this logger if you want to log your DNS traffic to a file in plain text mode or binary mode.
* with rotation file support
* supported format: `text`, `json` and `flat json`, `pcap` or `dnstap`
* gzip compression
* execute external command after each rotation
* custom text format

For config examples, take a look to the following links:
- [`text`](https://github.com/dmachard/go-dns-collector/blob/main/example-config/use-case-7.yml)
- [`dnstap`](https://github.com/dmachard/go-dns-collector/blob/main/example-config/use-case-13.yml)
- [`pcap`](https://github.com/dmachard/go-dns-collector/blob/main/example-config/use-case-1.yml)

Options:
- `file-path`: (string) output logfile name
- `max-size`: (integer) maximum size in megabytes of the file before rotation, A minimum of max-size*max-files megabytes of space disk must be available
- `max-files`: (integer) maximum number of files to retain. Set to zero if you want to disable this feature
- `flush-interval`: (integer) flush buffer to log file every X seconds
- `compress`: (boolean) compress log file
- `compress-interval`: (integer) checking every X seconds if new log files must be compressed
- `compress-command`: (string) run external script after file compress step
- `mode`: (string)  output format: text|json|pcap|dnstap|flat-json
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

The `postrotate-command` can be used to execute a script after each file rotation.
Your script will take in argument the path file of the latest log file and then you will can do what you want on it.
If the compression is enabled then the postrotate command will be executed after that too.

Basic example to use the postrotate command:


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

For the `PCAP` mode, currently the DNS protocol over UDP is used to log the traffic, the following translations are done.

| Origin protocol        | Translated to                  | 
| -----------------------|--------------------------------| 
| DNS/53 over UDP        | DNS UDP/53                     | 
| DNS/53 over TCP        | DNS UDP/53                     | 
| DoH/443                | DNS UDP/443                    | 
| DoT/853                | DoT/853 (no cipher)            | 
| DoQ                    | Not yet supported              | 


### DNStap Client

DNStap stream logger to a remote tcp destination or unix socket.
* to remote tcp destination or unix socket
* tls support

Options:
- `listen-ip`: (string) remote address
- `listen-port`: (integer) remote tcp port
- `sock-path`: (string) unix socket path
- `connect-timeout`: (integer) connect timeout in second
- `retry-interval`: (integer) interval in second between retry reconnect
- `flush-interval`: (integer) interval in second before to flush the buffer
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `server-id`: (string) server identity
- `overwrite-identity`: (boolean) overwrite original identity
- `buffer-size`: (integer) number of dns messages in buffer

Default values:

```yaml
dnstap:
  remote-address: 10.0.0.1
  remote-port: 6000
  sock-path: null
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  server-id: "dnscollector"
  overwrite-identity: false
  buffer-size: 100
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
- `connect-timeout`: (integer) connect timeout in second
- `retry-interval`: (integer) interval in second between retry reconnect
- `flush-interval`: (integer) interval in second before to flush the buffer
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `mode`: (string)  output format: text|json
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `buffer-size`: (integer) number of dns messages in buffer

Default values:

```yaml
tcpclient:
  transport: tcp
  remote-address: 127.0.0.1
  remote-port: 9999
  sock-path: null
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  mode: json
  text-format: ""
  buffer-size: 100
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
- `mode`: (string) text, json or flat-json
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `format`: (string) Set syslog formatter between `unix` (default), [`rfc3164`](https://www.rfc-editor.org/rfc/)rfc3164 ) or [`rfc5424`](https://www.rfc-editor.org/rfc/rfc5424)

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
  format: ""
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
- `connect-timeout`: (integer) connect timeout in second
- `retry-interval`: (integer) interval in second between retry reconnect
- `flush-interval`: (integer) interval in second before to flush the buffer
- `tag`: (string) tag name
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `buffer-size`: (integer) number of dns messages in buffer

Default values:

```yaml
fluentd:
  transport: tcp
  remote-address: 127.0.0.1
  remote-port: 24224
  sock-path: null
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tag: "dns.collector"
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  buffer-size: 100
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
- `mode`: (string) text, json or flat json
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
  text-format: ""
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

### Scalyr client
Client for the Scalyr/DataSet [`addEvents`](https://app.eu.scalyr.com/help/api#addEvents) API endpoint.

Options:
- `server-url`: (string) Scalyr API Host
- `apikey`: (string, required) API Token with Log Write permissions
- `mode`: (string) text, json, or flat-json
- `parser`: (string) When using text or json mode, the name of the parser Scalyr should use
- `flush-interval`: (integer) flush batch every X seconds
- `batch-size`: (integer) batch size for log entries in bytes
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `proxy-url`: (string) Proxy URL
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version
- `session-info`: (map) Any "session" or server information for Scalyr. e.g. 'region', 'serverHost'. If 'serverHost' is not included, it is set using the hostname.
- `attrs`: (map) Any extra attributes that should be added to the log's fields.

The client can send the data in 3 formats: text (using `text-format`), json (by including the whole DNS message in the `message` field), or flat-json.
The first two formats (text, json) require setting the `parser` option and needs a corresponding parser defined in the Scalyr backend.
As Scalyr's JSON parsers (like 'dottedJSON') will not expand nested JSON and require one or more 'rewrite' statements, the Scalyr client supports a `flat-json` mode.

Defaults:
```yaml
scalyrclient:
  server-url: app.scalyr.com
  apikey: ""
  mode: text
  text-format: "timestamp-rfc3339ns identity operation rcode queryip queryport family protocol length qname qtype latency"
  sessioninfo: {}
  attrs: {}
  parser: ""
  flush-interval: 30
  proxy-url: ""
  tls-insecure: false
  tls-min-version: 1.2
```

### Redis Pub

Redis Pub logger
* to remote tcp destination or unix socket
* supported format: text, json
* custom text format
* tls support

Options:
- `transport`: (string) network transport to use: tcp|unix
- `listen-ip`: (string) remote address
- `listen-port`: (integer) remote tcp port
- `sock-path`: (string) unix socket path
- `connect-timeout`: (integer) connect timeout in second
- `retry-interval`: (integer) interval in second between retry reconnect
- `flush-interval`: (integer) interval in second before to flush the buffer
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `mode`: (string)  output format: text|json
- `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
- `buffer-size`: (integer) number of dns messages in buffer
- `redis-channel`: (string) name of the redis pubsub channel to publish into

Default values:

```yaml
redispub:
  transport: tcp
  remote-address: 127.0.0.1
  remote-port: 6379
  sock-path: null
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  mode: json
  text-format: ""
  buffer-size: 100
  redis-channel: dns-collector
```