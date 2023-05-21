# Logger: DNStap Client

DNStap stream logger to a remote tcp destination or unix socket.
* to remote tcp destination or unix socket
* tls support

Options:
- `listen-ip`: (string) remote address
- `listen-port`: (integer) remote tcp port
- `sock-path`: (string) unix socket path
- `connect-timeout`: (integer) connect timeout in second
- `retry-interval`: (integer) interval in second between retry reconnect
- `flush-interval`: (integer) interval in second before to flush the buffer
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `server-id`: (string) server identity
- `overwrite-identity`: (boolean) overwrite original identity
- `buffer-size`: (integer) how many DNS messages will be buffered before being sent
- `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.

Default values:

```yaml
dnstap:
  remote-address: 10.0.0.1
  remote-port: 6000
  sock-path: null
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  server-id: "dnscollector"
  overwrite-identity: false
  buffer-size: 100
  chan-buffer-size: 65535
```
