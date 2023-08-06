# DNS-collector - Supported loggers

| Loggers                                 | Descriptions                                          |
| :-------------------------------------- |:------------------------------------------------------|
| [Console](logger_stdout.md)             | Print logs to stdout in text, json or binary formats. |
| [File](logger_file.md)                  | Save logs to file in plain text or binary formats     |
| [DNStap](logger_dnstap.md)              | Send logs as DNStap format to a remote collector      |
| [Prometheus](logger_prometheus.md)      | Expose metrics                                        |
| [Statsd](logger_statsd.md)              | Expose metrics                                        |
| [Rest API](logger_restapi.md)           | Search domains, clients in logs                       |
| [TCP](logger_tcp.md)                    | Tcp stream client logger                              |
| [Syslog](logger_syslog.md)              | Syslog logger to local syslog system or remote one.   |
| [Fluentd](logger_fluentd.md)            | Send logs to Fluentd server                           |
| [InfluxDB](logger_influxdb.md)          | Send logs to InfluxDB server                          |
| [Loki](logger_loki.md)                  | Send logs to Loki server                              |
| [ElasticSearch](logger_elasticserch.md) | Send logs to Elastic instance                         |
| [Scalyr](logger_scalyr.md)              | Client for the Scalyr/DataSet addEvents API endpoint. |
| [Redis](logger_redis.md)                | Redis pub logger                                      |
| [Kafka](logger_kafka.md)                | Kafka DNS producer                                    |
| [Falco](logger_falco.md)                | Falco plugin logger                                   |
