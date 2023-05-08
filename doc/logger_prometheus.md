
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

## Metrics

The full metrics can be found [here](metrics.txt).

| Metric                                          | Notes
|-------------------------------------------------|------------------------------------
| dnscollector_build_info                         | Build info
| dnscollector_domains_sf_uniq_total              | The total number of uniq Servfail domains
| dnscollector_nxdomains_total                    | The total number of NX domains per stream identity
| dnscollector_domains_nx_uniq_total              | The total number of uniq NX domains
| dnscollector_domains_total                      | The total number of domains per stream identity
| dnscollector_domains_uniq_total                 | The total number of uniq domains
| dnscollector_packets_total                      | Counter of packets
| dnscollector_qnames_size_bytes_bucket           | Size of the qname in bytes.
| dnscollector_queries_size_bytes_bucket          | Size of the queries in bytes.
| dnscollector_replies_size_bytes_bucket          | Size of the replies in bytes.
| dnscollector_requesters_total                   | The total number of DNS clients per stream identity
| dnscollector_requesters_uniq_total              | The total number of uniq DNS clients
| dnscollector_sent_bytes_total                   | The total bytes sent
| dnscollector_received_bytes_total               | The total bytes received
| dnscollector_throughput_ops                     | Number of ops per second received, partitioned by stream
| dnscollector_throughput_ops_max                 | Max number of ops per second observed, partitioned by stream
| dnscollector_tlds_total                         | The total number of tld per stream identity
| dnscollector_tlds_uniq_total                    | The total number of uniq TLD
| dnscollector_top_domains                        | Number of hit per domain topN, partitioned by stream and qname
| dnscollector_top_nxdomains                      | Number of hit per nx domain topN, partitioned by stream and qname
| dnscollector_top_sfdomains                      | Number of hit per servfail domain topN, partitioned by stream and qname
| dnscollector_top_requesters                     | Number of hit per requester topN, partitioned by client IP
| dnscollector_top_tlds                           | Number of hit per tld - topN
| dnscollector_top_unanswered                     | Number of hit per unanswered domain - topN
| dnscollector_unanswered_total                   | The total number of unanswered domains per stream identity
| dnscollector_unanswered_uniq_total              | The total number of uniq unanswered domain
| dnscollector_suspicious_total                   | The total number of unanswered domains per stream identity
| dnscollector_suspicious_uniq_total              | The total number of uniq suspicious domain

## Grafana Dashboards

Build-in dashboard are available with multiple data source

- [Prometheus](https://grafana.com/grafana/dashboards/16630)
- [Loki](https://grafana.com/grafana/dashboards/15415)

Activate the **[Prometheus](https://github.com/dmachard/go-dns-collector/blob/main/doc/loggers.md#prometheus)** logger to use this dashboard

<p align="center">
  <img src="dashboard_prometheus.png" alt="dnscollector"/>
</p>

## Loki Dashboard

<p align="center">
  <img src="dashboard_loki.png" alt="dnscollector"/>
</p>