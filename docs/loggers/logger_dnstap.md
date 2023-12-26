# Logger: DNStap Client

DNStap stream logger to a remote tcp/tls destination or unix socket.

Options:

* `transport`: (string) network transport to use: `unix`|`tcp`|`tcp+tls`
* `remote-address`: (string) remote address
* `remote-port`: (integer) remote tcp port
* `sock-path` **DEPRECATED, replaced by remote-address**: (string) unix socket path
* `connect-timeout`: (integer) connect timeout in second
* `retry-interval`: (integer) interval in second between retry reconnect
* `flush-interval`: (integer) interval in second before to flush the buffer
* `tls-support` **DEPRECATED, replaced with tcp+tls flag on transport**: (boolean) enable tls
* `tls-insecure`: (boolean) insecure skip verify
* `tls-min-version`: (string) min tls version, default to 1.2
* `ca-file`: (string) provide CA file to verify the server certificate
* `cert-file`: (string) provide client certificate file for mTLS
* `key-file`: (string) provide client private key file for mTLS
* `server-id`: (string) server identity
* `overwrite-identity`: (boolean) overwrite original identity
* `buffer-size`: (integer) how many DNS messages will be buffered before being sent
* `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.

Default values:

```yaml
dnstapclient:
  transport: tcp
  remote-address: 10.0.0.1
  remote-port: 6000
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  server-id: "dnscollector"
  overwrite-identity: false
  buffer-size: 100
  chan-buffer-size: 65535
```
