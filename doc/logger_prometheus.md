
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

The full metrics can be found [here](metrics.txt).

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