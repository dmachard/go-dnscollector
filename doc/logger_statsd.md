# Logger: Statsd client

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
