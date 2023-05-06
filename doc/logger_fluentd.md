
# Logger: Fluentd Client

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
