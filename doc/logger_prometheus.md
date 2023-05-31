
# Logger: Prometheus

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
- `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.
- `histogram-metrics-enabled`: (boolean) compute histogram for qnames length, latencies, queries and replies size repartition

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
  chan-buffer-size: 65535
  histogram-metrics-enabled: false
```

Scrape metric with curl:

```
$ curl -u admin:changeme http://127.0.0.1:8080/metrics
```

## Metrics

The full metrics can be found [here](metrics.txt).

| Metric                                          | Notes
|-------------------------------------------------|------------------------------------
| dnscollector_build_info                         | Build info
| dnscollector_requesters_total                   | The total number of requesters per stream identity
| dnscollector_nxdomains_total                    | The total number of NX domains per stream identity
| dnscollector_domains_total                      | The total number of domains per stream identity
| dnscollector_dnsmessage_total                   | Counter of total of DNS messages
| dnscollector_queries_total                      | Counter of total of queries
| dnscollector_replies_total                      | Counter of total of replies
| dnscollector_qtypes_total                       | Counter of total of queries per qtypes
| dnscollector_dnsmessage_total                   | Counter of total of DNS messages
| dnscollector_ipprotocol_total                   | The total number of DNS messages per IP protocol (UDP, TCPs)
| dnscollector_ipversion_total                    | The total number of DNS messages per IP version (v4, v6)
| dnscollector_bytes_total                        | The total bytes sent and received
| dnscollector_sent_bytes_total                   | The total bytes sent
| dnscollector_received_bytes_total               | The total bytes received
| dnscollector_flag_tc_total                      | Total of DNS messages with TC flag
| dnscollector_flag_aa_total                      | Total of DNS messages with AA flag
| dnscollector_flag_ra_total                      | Total of DNS messages with RA flag
| dnscollector_flag_ad_total                      | Total of DNS messages with AD flag
| dnscollector_malformed_total                    | Total of malformed DNS messages
| dnscollector_fragmented_total                   | Total of fragmented DNS messages (IP level)
| dnscollector_reassembled_total                  | Total of reassembled DNS messages (TCP level)
| dnscollector_throughput_ops                     | Number of ops per second received, partitioned by stream
| dnscollector_throughput_ops_max                 | Max number of ops per second observed, partitioned by stream
| dnscollector_tlds_total                         | The total number of tld per stream identity
| dnscollector_top_domains                        | Number of hit per domain topN, partitioned by stream and qname
| dnscollector_top_nxdomains                      | Number of hit per nx domain topN, partitioned by stream and qname
| dnscollector_top_sfdomains                      | Number of hit per servfail domain topN, partitioned by stream and qname
| dnscollector_top_requesters                     | Number of hit per requester topN, partitioned by client IP
| dnscollector_top_tlds                           | Number of hit per tld - topN
| dnscollector_top_unanswered                     | Number of hit per unanswered domain - topN
| dnscollector_unanswered_total                   | The total number of unanswered domains per stream identity
| dnscollector_suspicious_total                   | The total number of unanswered domains per stream identity
| dnscollector_qnames_size_bytes_bucket           | Histogram of the size of the qname in bytes
| dnscollector_queries_size_bytes_bucket          | Histogram of the size of the queries in bytes.
| dnscollector_replies_size_bytes_bucket          | Histogram of the size of the replies in bytes.

## Grafana dashboard with prometheus datasource

The following [build-in](https://grafana.com/grafana/dashboards/16630) dashboard is available

<p align="center">
  <img src="dashboard_prometheus.png" alt="dnscollector"/>
</p>

