
# Logger: Syslog

Syslog logger to local syslog system or remote one.

* local or remote server
* custom text format
* supported format: text, json or flat-json
* tls support

Options:

* `facility`: (string)
  > Set the syslog logging facility
* `transport`: (string)
  > Transport to use to a remote log daemon or local one. `local`|`tcp`|`udp`|`unix`|`tcp+tls`
* `remote-address`: (string)
  > Remote address host:port
* `retry-interval`: (integer)
  > interval in second between retry reconnect
* `mode`: (string)
  > output format: `text`, `json`, or `flat-json`
* `text-format`: (string)
  > output text format, please refer to the default text format to see all available [directives](../configuration.md#custom-text-format), use this parameter if you want a specific format
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
- `formattter`: (string)
  > Set syslog formatter between `unix`, `rfc3164` or `rfc5424`
- `framer`: (string)
  > Set syslog framer: `none` or `rfc5425`
- `hostname`: (string)
  > Set syslog hostname
- `app-name`: (string)
  > Set syslog program name
- `tag`: (string)
  > syslog tag or MSGID
- `replace-null-char`: (string)
  > replace NULl char in Qname with the specified character
- `buffer-size`: (integer)
  > how many DNS messages will be buffered before being sent
- `flush-interval`: (integer)
  > interval in second before to flush the buffer

Default values:

```yaml
syslog:
  severity: INFO
  facility: DAEMON
  transport: local
  remote-address: ""
  chan-buffer-size: 65535
  retry-interval: 10
  text-format: ""
  mode: text
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  formatter: "rfc3164"
  framer: ""
  hostname: ""
  app-name: ""
  tag: ""
  replace-null-char: "�"
  flush-interval: 30
  buffer-size: 100
```
