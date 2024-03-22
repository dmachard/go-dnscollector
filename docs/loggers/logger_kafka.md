# Logger: Kafka Producer

Kafka producer, based on [kafka-go](https://github.com/segmentio/kafka-go) library.

Options:

- `remote-address` (string) remote address. Default to `127.0.0.1`.
  > Specifies the remote address to connect to.
- `remote-port` (integer) remote tcp port. Default to `9092`.
  > Specifies the remote TCP port to connect to.
- `connect-timeout` (integer) connect timeout in second. Default to `5` seconds.
  > Specifies the maximum time to wait for a connection attempt to complete.
- `retry-interval` (integer) interval in second between retry reconnect. Default to `10` seconds.
  > Specifies the interval between attempts to reconnect in case of connection failure.
- `flush-interval` (integer) interval in second before to flush the buffer. Default to `30` seconds.
  > Specifies the interval between buffer flushes.
- `tls-support` (boolean) enable TLS. Default to `false`.
  > Enables or disables TLS (Transport Layer Security) support. If set to true, TLS will be used for secure communication.
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
- `sasl-support` (boolean) enable SASL. Default to `false`.
  > Enable or disable SASL (Simple Authentication and Security Layer) support for Kafka.
- `sasl-username` (string) SASL username. Default to `(empty)`.
  > Specifies the SASL username for authentication with Kafka brokers.
- `sasl-password` (string) SASL password. Default to `(empty)`.
  > Specifies the SASL password for authentication with Kafka brokers.
- `sasl-mechanism` (string) SASL mechanism: `PLAIN` or `SCRAM-SHA-512`. Default to `PLAIN`.
  > Specifies the SASL mechanism to use for authentication with Kafka brokers.
- `mode` (string)  output format: `text`, `json`, or `flat-json`. Default to `flat-json`.
  > Specifies the output format for Kafka messages.
- `buffer-size` (integer) how many DNS messages will be buffered before being sent. Default to `100`.
  > Specifies the size of the buffer for DNS messages before they are sent to Kafka.
- `topic` (integer) kafka topic to forward messages to. Default to `dnscollector`.
  > Specifies the Kafka topic to which messages will be forwarded.
- `partition` (integer) kafka partition. Default to `0`.
  > Specifies the Kafka partition to which messages will be sent.
- `chan-buffer-size` (int) incoming channel size, number of packet before to drop it. Default to `4096`.
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.
- `compression` (string) Compression for Kafka messages: `none`, `gzip`, `lz4`, `snappy`, `zstd`. Default to `none`.
  > Specifies the compression algorithm to use for Kafka messages.
