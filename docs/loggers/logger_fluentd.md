
# Logger: Fluentd Client

Fluentd client to remote server or unix socket.
Based on [IBM/fluent-forward-go](https://github.com/IBM/fluent-forward-go) library

Options:

* `transport` (string)
  > network transport to use: `tcp`|`unix`|`tcp+tls`.
  > Specifies the transport ot use.

* `remote-address` (string)
  > Specifies the remote address to connect to.

* `remote-port` (integer)
  > Specifies the remote TCP port to connect to.

* `connect-timeout` (integer)
  > Specifies the maximum time to wait for a connection attempt to complete.

* `retry-interval` (integer)
  > Specifies the interval between attempts to reconnect in case of connection failure.

* `flush-interval` (integer)
  > Specifies the interval between buffer flushes.

* `tag` (string) tag name.
  > Specifies the tag to use.

* `tls-insecure` (boolean)
  > If set to true, skip verification of server certificate.

* `tls-min-version` (string)
  > Specifies the minimum TLS version that the server will support.

* `ca-file` (string)
  > Specifies the path to the CA (Certificate Authority) file used to verify the server's certificate.

* `cert-file` (string)
  > Specifies the path to the certificate file to be used. This is a required parameter if TLS support is enabled.

* `key-file` (string)
  > Specifies the path to the key file corresponding to the certificate file.
  > This is a required parameter if TLS support is enabled.

* `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

Defaults:

```yaml
fluentd:
  transport: tcp
  remote-address: 127.0.0.1
  remote-port: 24224
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tag: dns.collector
  tls-insecure: false
  tls-min-version: "1.2"
  tls-min-version: ""
  ca-file: ""
  cert-file: ""
  key-file: ""
  chan-buffer-size: 0
```
