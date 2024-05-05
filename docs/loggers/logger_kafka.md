# Logger: Kafka Producer

Kafka producer, based on [kafka-go](https://github.com/segmentio/kafka-go) library.

Options:

* `remote-address` (string)
  > Remote address.
  > Specifies the remote address to connect to.

* `remote-port` (integer)
  > Remote tcp port.
  > Specifies the remote TCP port to connect to.

* `connect-timeout` (integer)
  > Specifies the maximum time to wait for a connection attempt to complete.

* `retry-interval` (integer)
  > Specifies the interval between attempts to reconnect in case of connection failure.

* `flush-interval` (integer)
  > Specifies the interval between buffer flushes.

* `tls-support` (boolean)
  > Enables or disables TLS (Transport Layer Security) support.
  > If set to true, TLS will be used for secure communication.

* `tls-insecure` (boolean)
  > If set to true, skip verification of server certificate.

* `tls-min-version` (string)
  > Specifies the minimum TLS version that the server will support.

* `ca-file` (string)
  > Specifies the path to the CA (Certificate Authority) file used to verify the server's certificate.

* `cert-file` (string)
  > Specifies the path to the certificate file to be used. This is a required parameter if TLS support is enabled.

* `key-file` (string)
  > Specifies the path to the key file corresponding to the certificate file. This is a required parameter if TLS support is enabled.

* `sasl-support` (boolean)
  > Enable or disable SASL (Simple Authentication and Security Layer) support for Kafka.

* `sasl-username` (string)
  > Specifies the SASL username for authentication with Kafka brokers.

* `sasl-password` (string)
  > Specifies the SASL password for authentication with Kafka brokers

* `sasl-mechanism` (string)
  > Specifies the SASL mechanism to use for authentication with Kafka brokers.
  > SASL mechanism: `PLAIN` or `SCRAM-SHA-512`.

* `mode` (string)
  > Specifies the output format for Kafka messages. Output format: `text`, `json`, or `flat-json`.

* `text-format` (string)
  > output text format, please refer to the default text format to see all available [directives](../configuration.md#custom-text-format), use this parameter if you want a specific format

* `buffer-size` (integer)
  > Specifies the size of the buffer for DNS messages before they are sent to Kafka.

* `topic` (integer)
  > Specifies the Kafka topic to which messages will be forwarded.

* `partition` (integer)
  > Specifies the Kafka partition to which messages will be sent.

* `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.

* `compression` (string)
  > Specifies the compression algorithm to use for Kafka messages.
  > Compression for Kafka messages: `none`, `gzip`, `lz4`, `snappy`, `zstd`.

Defaults:

```yaml
kafkaproducer:
  remote-address: 127.0.0.1
  remote-port: 9092
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-support: false
  tls-insecure: false
  sasl-support: false
  sasl-mechanism: PLAIN
  sasl-username: false
  sasl-password: false
  mode: flat-json
  text-format: ""
  buffer-size: 100
  topic: "dnscollector"
  partition: 0
  chan-buffer-size: 4096
  compression: none
```
