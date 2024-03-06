
# Logger: Fluentd Client

Fluentd client to remote server or unix socket.
Based on [IBM/fluent-forward-go](https://github.com/IBM/fluent-forward-go) library

Options:

- `transport` (string) network transport to use: `tcp`|`unix`|`tcp+tls`. Default to `tcp`.
  > Specifies the transport ot use.
- `remote-address` (string) remote address.
  > Specifies the remote address to connect to. Default to `127.0.0.1`.
- `remote-port` (integer) remote tcp port. Default to `24224`.
  > Specifies the remote TCP port to connect to.
- `connect-timeout` (integer) connect timeout in second. Default to `5` seconds.
  > Specifies the maximum time to wait for a connection attempt to complete.
- `retry-interval` (integer) interval in second between retry reconnect. Default to `10` seconds.
  > Specifies the interval between attempts to reconnect in case of connection failure.
- `flush-interval` (integer) interval in second before to flush the buffer. Default to `30` seconds.
  > Specifies the interval between buffer flushes.
- `tag` (string) tag name. Default to `dns.collector`.
  > Specifies the tag to use.
- `tls-insecure` (boolean) insecure skip verify. Default to `false`.
  > If set to true, skip verification of server certificate.
- `tls-min-version` (string) min tls version. Default to `1.2`.
  > Specifies the minimum TLS version that the server will support.
- `ca-file` (string) provide CA file to verify the server certificate. Default to `(empty)`.
  > Specifies the path to the CA (Certificate Authority) file used to verify the server's certificate.
- `cert-file` (string) provide client certificate file for mTLS. Default to `(empty)`.
  > Specifies the path to the certificate file to be used. This is a required parameter if TLS support is enabled.
- `key-file` (string) provide client private key file for mTLS. Default to `(empty)`.
  > Specifies the path to the key file corresponding to the certificate file. This is a required parameter if TLS support is enabled.
- `chan-buffer-size` (int) incoming channel size, number of packet before to drop it. Default to `4096`.
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.

