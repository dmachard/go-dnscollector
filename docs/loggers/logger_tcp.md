
# Logger: TCP Client

Tcp/unix stream client logger.

* to remote tcp destination or unix socket
* supported format: text, json
* custom text format
* tls support

Options:

* `transport`: (string) network transport to use: tcp|unix|tcp+tls
* `remote-ip`: (string) remote address
* `remote-port`: (integer) remote tcp port
* `sock-path` **DEPRECATED**: (string) unix socket path
* `connect-timeout`: (integer) connect timeout in second
* `retry-interval`: (integer) interval in second between retry reconnect
* `flush-interval`: (integer) interval in second before to flush the buffer
* `tls-support` **DEPRECATED**: (boolean) enable tls
* `tls-insecure`: (boolean) insecure skip verify
* `tls-min-version`: (string) min tls version, default to 1.2
* `ca-file`: (string) provide CA file to verify the server certificate
* `cert-file`: (string) provide client certificate file for mTLS
* `key-file`: (string) provide client private key file for mTLS
* `mode`: (string) output format: text, json, or flat-json
* `text-format`: (string) output text format, please refer to the default text format to see all available directives, use this parameter if you want a specific format
* `buffer-size`: (integer) how many DNS messages will be buffered before being sent
* `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.

Default values:

```yaml
tcpclient:
  transport: tcp
  remote-address: 127.0.0.1
  remote-port: 9999
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  mode: json
  text-format: ""
  buffer-size: 100
  chan-buffer-size: 65535
```
