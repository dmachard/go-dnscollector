
# Logger: Redis Pub

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
- `mode`: (string)  output format: text, json, or flat-json
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
