# Logger: DNStap Client

DNStap stream logger to a remote tcp/tls destination or unix socket.

Options:

* `transport` (string)
  > network transport to use: `unix`|`tcp`|`tcp+tls`

* `remote-address` (string)
  > remote address

* `remote-port` (integer)
  > remote tcp port

* `connect-timeout` (integer)
  > connect timeout in second

* `retry-interval` (integer)
  > interval in second between retry reconnect

* `flush-interval` (integer)
  > interval in second before to flush the buffer

* `tls-insecure` (boolean)
  > insecure skip verify

* `tls-min-version` (string)
  > minimum tls version to use

* `ca-file` (string)
  > provide CA file to verify the server certificate

* `cert-file` (string)
  > provide client certificate file for mTLS

* `key-file` (string)
  > provide client private key file for mTLS

* `server-id` (string)
  > server identity

* `overwrite-identity` (boolean)
  > overwrite original identity

* `buffer-size` (integer)
  > how many DNS messages will be buffered before being sent

* `chan-buffer-size` (integer)
  > Specifies the maximum number of packets that can be buffered before discard additional packets.
  > Set to zero to use the default global value.

* `extended-support` (boolen)
  > Extend the DNStap message by incorporating additional transformations, such as filtering and ATags, into the extra field.

* `compression` (string)
  > Compression for DNStap messages: `none`, `gzip`, `lz4`, `snappy`, `zstd`. Default to `none`.
  > Specifies the compression algorithm to use.

Defaults:

```yaml
- name: dnstap
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
    chan-buffer-size: 0
    extended-support: false
    compression: none
```
