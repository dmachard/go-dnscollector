
# Logger: Syslog

Syslog logger to local syslog system or remote one.

* local or remote server
* custom text format
* supported format: text, json or flat-json
* tls support

Options:

* `facility`: (string) Set the syslog logging facility
* `transport`: (string) Transport to use to a remote log daemon or local one. `local`|`tcp`|`udp`|`unix`|`tcp+tls`
* `remote-address`: (string) Remote address host:port
* `retry-interval`: (integer) interval in second between retry reconnect
* `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.
* `mode`: (string) output format: `text`, `json`, or `flat-json`
* `text-format`: (string) output text format, please refer to the default text format to see all available [directives](../configuration.md#custom-text-format), use this parameter if you want a specific format
* `tls-insecure`: (boolean) insecure mode, skip certificate verify
* `tls-min-version`: (string) min tls version, default to 1.2
* `ca-file`: (string) provide CA file to verify the server certificate
* `cert-file`: (string) provide client certificate file for mTLS
* `key-file`: (string) provide client private key file for mTLS
* `formattter`: (string) Set syslog formatter between `unix`, `rfc3164` or `rfc5424`
* `framer`: (string) Set syslog framer: `none` or `rfc5425`
* `hostname`: (string) Set syslog hostname
* `app-name`: (string) Set syslog program name
* `tag`: (string) syslog tag or MSGID
* `replace-null-char`: (string) replace NULl char in Qname with the specified character

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
  replace-null-char: "|"
```
