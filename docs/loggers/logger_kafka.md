# Logger: Kafka Producer

Kafka producer

Options:

- `remote-address`: (string) remote address
- `remote-port`: (integer) remote tcp port
- `connect-timeout`: (integer) connect timeout in second
- `retry-interval`: (integer) interval in second between retry reconnect
- `flush-interval`: (integer) interval in second before to flush the buffer
- `tls-support`: (boolean) enable tls
- `tls-insecure`: (boolean) insecure skip verify
- `tls-min-version`: (string) min tls version, default to 1.2
- `ca-file`: (string) provide CA file to verify the server certificate
- `cert-file`: (string) provide client certificate file for mTLS
- `key-file`: (string) provide client private key file for mTLS
- `sasl-support`: (boolean) enable SASL
- `sasl-username`: (string) SASL username
- `sasl-password`: (string) SASL password
- `sasl-mechanism`: (string) SASL mechanism: `PLAIN` or `SCRAM-SHA-512`
- `mode`: (string)  output format: `text`, `json`, or `flat-json`
- `buffer-size`: (integer) how many DNS messages will be buffered before being sent
- `topic`: (integer) kafka topic to forward messages to
- `partition`: (integer) kafka partition
- `chan-buffer-size`: (integer) channel buffer size used on incoming dns message, number of messages before to drop it.
- `compression`: (string) Compression for Kafka messages: none, gzip, lz4, snappy, zstd

Default values:

```yaml
kafkaproducer:
  remote-address: 127.0.0.1
  remote-port: 9092
  connect-timeout: 5
  retry-interval: 10
  flush-interval: 30
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  sasl-support: false
  sasl-mechanism: PLAIN
  sasl-username: ""
  sasl-password: ""
  mode: flat-json
  buffer-size: 100
  topic: "dnscollector"
  partition: 0
  chan-buffer-size: 65535
  compression: "none"
```
