
# Logger: InfluxDB client

InfluxDB client to remote InfluxDB server

Options:

* `server-url`: (string)
  > InfluxDB server url

* `auth-token`: (string)
  > authentication token

* `bucket`: (string)
  > bucket name

* `organization`: (string)
  > organization name

* `tls-support`: (boolean)
  > enable tls

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

* `chan-buffer-size` (int)
  > Specifies the maximum number of packets that can be buffered before dropping additional packets.

Default values:

```yaml
influxdb:
  server-url: "http://localhost:8086"
  auth-token: ""
  bucket: "db_dns"
  organization: "dnscollector"
  tls-support: false
  tls-insecure: false
  tls-min-version: 1.2
  ca-file: ""
  cert-file: ""
  key-file: ""
  chan-buffer-size: 65535
```
