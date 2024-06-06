# DNS-collector - Supported Collectors & Loggers

A worker can act as a collector or a logger.

| Worker                                                | Type      | Descriptions                                            |
| :-----------------------------------------------------|:----------|:--------------------------------------------------------|
| [DNStap Server](collectors/collector_dnstap.md)       | Collector | DNStap receiver and proxifier                           |
| [PowerDNS](collectors/collector_powerdns.md)          | Collector | Protobuf PowerDNS receiver                              |
| [Tail](collectors/collector_tail.md)                  | Collector | Tail on plain text file                                 |
| [XDP Sniffer](collectors/collector_xdp.md)            | Collector | Live capture on network interface with XDP              |
| [AF_PACKET Sniffer](collectors/collector_afpacket.md) | Collector | Live capture on network interface with AF_PACKET socket |
| [File Ingestor](collectors/collector_fileingestor.md) | Collector | File ingestor like pcap                                 |
| [DNS Message](collectors/collector_dnsmessage.md)     | Collector | Matching specific DNS message                           |
| [Console](loggers/logger_stdout.md)                   | Logger    | Print logs to stdout in text, json or binary formats.   |
| [File](loggers/logger_file.md)                        | Logger    | Save logs to file in plain text or binary formats       |
| [DNStap Client](loggers/logger_dnstap.md)             | Logger    | Send logs as DNStap format to a remote collector        |
| [Prometheus](loggers/logger_prometheus.md)            | Logger    | Expose metrics                                          |
| [Statsd](loggers/logger_statsd.md)                    | Logger    | Expose metrics                                          |
| [Rest API](loggers/logger_restapi.md)                 | Logger    | Search domains, clients in logs                         |
| [TCP](loggers/logger_tcp.md)                          | Logger    | Tcp stream client logger                                |
| [Syslog](loggers/logger_syslog.md)                    | Logger    | Syslog logger to local syslog system or remote one.     |
| [Fluentd](loggers/logger_fluentd.md)                  | Logger    | Send logs to Fluentd server                             |
| [InfluxDB](loggers/logger_influxdb.md)                | Logger    | Send logs to InfluxDB server                            |
| [Loki Client](loggers/logger_loki.md)                 | Logger    | Send logs to Loki server                                |
| [ElasticSearch](loggers/logger_elasticsearch.md)      | Logger    | Send logs to Elastic instance                           |
| [Scalyr](loggers/logger_scalyr.md)                    | Logger    | Client for the Scalyr/DataSet addEvents API endpoint.   |
| [Redis publisher](loggers/logger_redis.md)            | Logger    | Redis pub logger                                        |
| [Kafka Producer](loggers/logger_kafka.md)             | Logger    | Kafka DNS producer                                      |
| [Falco](loggers/logger_falco.md)                      | Logger    | Falco plugin logger                                     |
| [ClickHouse](loggers/logger_clickhouse.md)            | Logger    | ClickHouse logger                                       |
