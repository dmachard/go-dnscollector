
# Logger: Redis Pub

Redis Pub logger

* to remote tcp destination or unix socket
* supported format: text, json
* custom text format
* tls support

Options:

-`transport` (string)
  > network transport to use: `tcp`|`unix`|`tcp+tls`

-`remote-address` (string)
  > remote IP or host address

-`remote-port` (integer)
  > remote tcp port

-`connect-timeout` (integer)
  > connect timeout in second

-`retry-interval` (integer)
  > interval in second between retry reconnect

-`flush-interval` (integer)
  > interval in second before to flush the buffer

-`tls-insecure` (boolean)
  > If set to true, skip verification of server certificate.

-`tls-min-version` (string)
  > Specifies the minimum TLS version that the server will support.

-`ca-file` (string)
  > Specifies the path to the CA (Certificate Authority) file used to verify the server's certificate.

-`cert-file` (string)
  > Specifies the path to the certificate file to be used. This is a required parameter if TLS support is enabled.

-`key-file` (string)
  > Specifies the path to the key file corresponding to the certificate file. This is a required parameter if TLS support is enabled.

-`chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.

-`mode` (string)
  > output format: `text`, `json`, or `flat-json`

-`text-format` (string)
  > output text format, please refer to the default text format to see all available [directives](../configuration.md#custom-text-format), use this parameter if you want a specific format

-`buffer-size` (integer)
  > how many DNS messages will be buffered before being sent

-`redis-channel` (string)
  > name of the redis pubsub channel to publish into

Default values:

```yaml
redispub:
  transport: tcp
  remote-address: 127.0.0.1
  remote-port: 6379
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  mode: flat-json
  text-format: ""
  buffer-size: 100
  redis-channel: dns-collector
  chan-buffer-size: 65535
```
