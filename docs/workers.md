# DNS-collector - Supported Collectors & Loggers

A worker can act as a collector or a logger.

| Worker                                                | Descriptions                                            |
| :-----------------------------------------------------|:--------------------------------------------------------|
| [DNStap](collectors/collector_dnstap.md)              | DNStap receiver and proxifier                           |
| [PowerDNS](collectors/collector_powerdns.md)          | Protobuf PowerDNS receiver                              |
| [Tail](collectors/collector_tail.md)                  | Tail on plain text file                                 |
| [XDP Sniffer](collectors/collector_xdp.md)            | Live capture on network interface with XDP              |
| [AF_PACKET Sniffer](collectors/collector_afpacket.md) | Live capture on network interface with AF_PACKET socket |
| [File Ingestor](collectors/collector_fileingestor.md) | File ingestor like pcap                                 |
| [DNS Message](collectors/collector_dnsmessage.md)     | Internal DNS data structure                             |
| [Console](loggers/logger_stdout.md)                   | Print logs to stdout in text, json or binary formats.   |
| [File](loggers/logger_file.md)                        | Save logs to file in plain text or binary formats       |
| [DNStap](loggers/logger_dnstap.md)                    | Send logs as DNStap format to a remote collector        |
| [Prometheus](loggers/logger_prometheus.md)            | Expose metrics                                          |
| [Statsd](loggers/logger_statsd.md)                    | Expose metrics                                          |
| [Rest API](loggers/logger_restapi.md)                 | Search domains, clients in logs                         |
| [TCP](loggers/logger_tcp.md)                          | Tcp stream client logger                                |
| [Syslog](loggers/logger_syslog.md)                    | Syslog logger to local syslog system or remote one.     |
| [Fluentd](loggers/logger_fluentd.md)                  | Send logs to Fluentd server                             |
| [InfluxDB](loggers/logger_influxdb.md)                | Send logs to InfluxDB server                            |
| [Loki](loggers/logger_loki.md)                        | Send logs to Loki server                                |
| [ElasticSearch](loggers/logger_elasticsearch.md)      | Send logs to Elastic instance                           |
| [Scalyr](loggers/logger_scalyr.md)                    | Client for the Scalyr/DataSet addEvents API endpoint.   |
| [Redis](loggers/logger_redis.md)                      | Redis pub logger                                        |
| [Kafka](loggers/logger_kafka.md)                      | Kafka DNS producer                                      |
| [Falco](loggers/logger_falco.md)                      | Falco plugin logger                                     |
| [ClickHouse](loggers/logger_clickhouse.md)            | ClickHouse logger                                       |