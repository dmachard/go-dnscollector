# Logger: Statsd client

Statsd client to statsd proxy

* tls support

**Statsd metrics:**

The `<statsdsuffix>` tag can be configured in the `config.yml` file.

Counters:

```bash
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

```bash
- <statsdsuffix>_<streamid>_queries_qps
```

Options:

* `transport`: (string) network transport to use: `udp` | `tcp` | `tcp+tls`
* `remote-address`: (string) remote address
* `remote-port`: (integer) remote tcp port
* `connect-timeout`: (integer) connect timeout in second
* `prefix`: (string) statsd prefix name
- `tls-insecure` (boolean)
  > If set to true, skip verification of server certificate.
- `tls-min-version` (string)
  > Specifies the minimum TLS version that the server will support.
- `ca-file` (string)
  > Specifies the path to the CA (Certificate Authority) file used to verify the server's certificate.
- `cert-file` (string)
  > Specifies the path to the certificate file to be used. This is a required parameter if TLS support is enabled.
- `key-file` (string)
  > Specifies the path to the key file corresponding to the certificate file. This is a required parameter if TLS support is enabled.
- `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.

Default values:

```yaml
statsd:
  transport: udp
  remote-address: 127.0.0.1
  remote-port: 8125
  prefix: "dnscollector"
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  chan-buffer-size: 65535
```
